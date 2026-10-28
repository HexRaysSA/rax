//! Fault-precise helper-backed MXCSR memory operations.

use crate::isa::x86_64::MXCSR_SUPPORTED_MASK;
use crate::smir::ir::ops::{OpKind, SmirOp, X86OpHint, X86SsePrefix, X86VecMap};
use crate::smir::ir::types::{ArchReg, DispSize, MemWidth, OpWidth, SignExtend, VReg, VecWidth};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{LowerError, X86_GUEST_CR0_OFFSET, X86_GUEST_MXCSR_OFFSET};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

const CR0_TS: i64 = 1 << 3;

/// Validate an exact legacy or VEX.LZ.WIG `LDMXCSR` shape emitted by the
/// strict x86-64 lifter. The next PC makes a successful state commit terminal,
/// while the APX marker proves that any EGPR address is dynamically guarded.
pub(crate) fn x86_load_mxcsr_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86LoadMxcsr {
        addr,
        requires_apx,
        next_pc,
    } = &op.kind
    else {
        return false;
    };
    let Some(length) = next_pc.checked_sub(op.guest_pc) else {
        return false;
    };
    let uses_egpr = addr
        .regs()
        .iter()
        .any(|reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()));
    if !addr.is_x86_state_backed_shape() || (uses_egpr && !requires_apx) {
        return false;
    }

    match op.x86_hint {
        // REX2.M=1 selects map 0F without a separate 0F byte, so the shortest
        // APX form is D5 payload AE ModR/M (4 bytes).
        None if *requires_apx => (4..=15).contains(&length),
        None => (3..=15).contains(&length),
        Some(X86OpHint::VexOp {
            map: X86VecMap::Map0F,
            pp: X86SsePrefix::None,
            opcode: 0xAE,
            width: VecWidth::V128,
            ..
        }) => !requires_apx && (4..=15).contains(&length),
        _ => false,
    }
}

/// Validate the exact legacy or VEX.LZ.WIG `STMXCSR` shape emitted by the
/// strict x86-64 lifter. The APX marker proves that a legacy REX2 form is
/// dynamically guarded; the VEX W bit is architecturally ignored.
pub(crate) fn x86_store_mxcsr_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86StoreMxcsr { addr, requires_apx } = &op.kind else {
        return false;
    };
    let uses_egpr = addr
        .regs()
        .iter()
        .any(|reg| matches!(reg, VReg::Arch(ArchReg::X86(x86)) if x86.is_egpr()));
    if !addr.is_x86_state_backed_shape() || (uses_egpr && !requires_apx) {
        return false;
    }

    match op.x86_hint {
        None => true,
        Some(X86OpHint::VexOp {
            map: X86VecMap::Map0F,
            pp: X86SsePrefix::None,
            opcode: 0xAE,
            width: VecWidth::V128,
            ..
        }) => !requires_apx && !uses_egpr,
        _ => false,
    }
}

impl X86_64Lowerer {
    /// Continue only while CR0.TS is clear. Failure restores the complete
    /// incoming native GPR/flag image and hands the faulting guest PC to direct
    /// execution for precise #NM delivery before any MXCSR memory access.
    fn emit_x86_mxcsr_ts_guard(&mut self, guest_pc: u64) -> Result<(), LowerError> {
        self.code.emit_u8(0x9C); // pushfq
        self.code.emit_u8(0x50); // push rax
        self.emit_load_state_ptr_rax();
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_test_mi_disp(
                PhysReg::Rax,
                X86_GUEST_CR0_OFFSET,
                DispSize::Auto,
                CR0_TS,
                OpWidth::W64,
            );
        }
        let enabled = self.emit_jcc_placeholder(X86Cond::E);

        self.code.emit_u8(0x58); // pop rax
        self.code.emit_u8(0x9D); // popfq
        self.emit_native_exit(guest_pc);

        self.patch_rel32_to_current(enabled)?;
        self.code.emit_u8(0x58); // pop rax
        self.code.emit_u8(0x9D); // popfq
        Ok(())
    }

    /// Load and validate a prospective MXCSR through the canonical 4-byte MMU
    /// helper. Faults, disabled APX, and reserved bits leave at the faulting
    /// guest PC without committing; success commits once and leaves at the
    /// completed-instruction frontier.
    pub(crate) fn emit_x86_load_mxcsr(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86LoadMxcsr requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !self.mem_helpers {
            return Err(LowerError::UnsupportedOp {
                op: "X86LoadMxcsr requires JIT MMU helpers".to_string(),
            });
        }
        if !x86_load_mxcsr_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86LoadMxcsr".to_string(),
                operand: "requires an exact legacy or VEX.LZ.WIG state-backed x86 load frontier"
                    .to_string(),
            });
        }
        let OpKind::X86LoadMxcsr {
            addr,
            requires_apx,
            next_pc,
        } = &op.kind
        else {
            unreachable!("validated MXCSR load shape changed")
        };

        if *requires_apx {
            self.emit_x86_require_apx_guard(op.guest_pc)?;
        }
        self.emit_x86_mxcsr_ts_guard(op.guest_pc)?;

        // The generic load-helper stages a complete u64 into this aligned
        // caller slot. A helper fault removes the slot before its exact exit.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -16);
        }
        self.emit_jit_mem_op(
            op.guest_pc,
            true,
            None,
            Some(16),
            None,
            None,
            None,
            addr,
            MemWidth::B4,
            SignExtend::Zero,
            16,
        )?;

        // Preserve the complete guest RFLAGS image across the reserved-bit
        // test. The staged value moves from [rsp] to [rsp+8].
        self.code.emit_u8(0x9C); // pushfq
        self.code.emit_bytes(&[0xF7, 0x44, 0x24, 0x08]); // test dword [rsp+8],imm32
        self.code.emit_u32(!MXCSR_SUPPORTED_MASK);
        let invalid = self.emit_jcc_placeholder(X86Cond::Ne);

        // Commit the validated low 32 bits through GuestRegs. In a native
        // vector region, also update the live host MXCSR: the outer trampoline
        // snapshots it back into GuestRegs before restoring the host value.
        self.code.emit_u8(0x50); // push rax; staged value is [rsp+16]
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x51); // push rcx; staged value is [rsp+24]
        self.code.emit_bytes(&[0x8B, 0x4C, 0x24, 0x18]); // mov ecx,[rsp+24]
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_mr(
                PhysReg::Rax,
                X86_GUEST_MXCSR_OFFSET,
                PhysReg::Rcx,
                OpWidth::W32,
            );
        }
        if self.preserve_vector_mem_helpers {
            self.code.emit_bytes(&[0x0F, 0xAE, 0x54, 0x24, 0x18]); // ldmxcsr [rsp+24]
        }
        self.code.emit_u8(0x59); // pop rcx
        self.code.emit_u8(0x58); // pop rax
        self.code.emit_u8(0x9D); // popfq
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
        }
        self.emit_x86_retirement();
        self.emit_native_exit(*next_pc);

        // Reserved bits produce #GP(0) on direct replay. No state was changed,
        // and the helper was read-only, so restarting at guest_pc is precise.
        self.patch_rel32_to_current(invalid)?;
        self.code.emit_u8(0x9D); // popfq
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
        }
        self.emit_native_exit(op.guest_pc);
        Ok(())
    }

    /// Store the current architectural MXCSR through the canonical 4-byte MMU
    /// helper. A helper failure restores every GPR and RFLAGS bit, removes the
    /// caller-owned staging slot, and exits at the faulting guest PC without a
    /// guest-memory commit.
    pub(crate) fn emit_x86_store_mxcsr(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86StoreMxcsr requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !self.mem_helpers {
            return Err(LowerError::UnsupportedOp {
                op: "X86StoreMxcsr requires JIT MMU helpers".to_string(),
            });
        }
        if !x86_store_mxcsr_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86StoreMxcsr".to_string(),
                operand: "requires a legacy or VEX.LZ.WIG state-backed x86 address".to_string(),
            });
        }
        let OpKind::X86StoreMxcsr { addr, requires_apx } = &op.kind else {
            unreachable!("validated MXCSR store shape changed")
        };
        if *requires_apx {
            self.emit_x86_require_apx_guard(op.guest_pc)?;
        }
        self.emit_x86_mxcsr_ts_guard(op.guest_pc)?;

        // Reserve one aligned caller slot without modifying flags. In a vector
        // region the live host MXCSR includes status accrued by preceding
        // native FP operations. Otherwise GuestRegs.mxcsr is authoritative and
        // can be staged with flag-neutral MOV/LEA bookkeeping.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, -16);
        }
        // The store-helper ABI transports a u64 even though the architectural
        // access is 4 bytes. Clear the complete staged value first so its
        // unused high half is deterministic for both STMXCSR and MOV sources.
        self.code
            .emit_bytes(&[0x48, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00]);
        if self.preserve_vector_mem_helpers {
            self.code.emit_bytes(&[0x0F, 0xAE, 0x1C, 0x24]); // stmxcsr [rsp]
        } else {
            self.code.emit_u8(0x50); // push guest RAX
            self.emit_load_state_ptr_rax();
            {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_rm(
                    PhysReg::Rax,
                    PhysReg::Rax,
                    X86_GUEST_MXCSR_OFFSET,
                    OpWidth::W32,
                );
                // After POP, the caller slot begins at [rsp].
                emitter.emit_mov_mr(PhysReg::Rsp, 8, PhysReg::Rax, OpWidth::W32);
            }
            self.code.emit_u8(0x58); // pop guest RAX
        }

        // The generic helper pushes guest RAX and RFLAGS, so caller [rsp] is
        // visible as [rsp+16] while it collects the store value.
        self.emit_jit_mem_op(
            op.guest_pc,
            false,
            None,
            None,
            None,
            None,
            Some(16),
            addr,
            MemWidth::B4,
            SignExtend::Zero,
            16,
        )?;
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_lea(PhysReg::Rsp, PhysReg::Rsp, 16);
        }
        Ok(())
    }
}

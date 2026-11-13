//! Fault-precise, helper-backed lowering for x86 control-register writes.

use crate::smir::ir::ops::{OpKind, SmirOp, X86ControlReg};
use crate::smir::ir::types::{ArchReg, OpWidth, VReg};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{LowerError, X86_GUEST_CONTROL_WRITE_FN_OFFSET, X86_STATE_PTR_AT_RBP};

use super::{X86_64Lowerer, X86Cond, X86Emitter};

/// Validate the complete shape emitted by the strict 64-bit MOV-to-CR lifter.
///
/// The instruction is at least three and at most fifteen bytes. Requiring an
/// exact, forward `next_pc` prevents malformed hand-built IR from selecting an
/// arbitrary native handoff frontier. REX2 permits every GPR through R31; the
/// preceding `X86RequireApx` operation retains the source encoding's dynamic
/// admission.
pub(crate) fn x86_write_control_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86WriteControl {
        src,
        control,
        next_pc,
    } = &op.kind
    else {
        return false;
    };
    let instruction_len = next_pc.checked_sub(op.guest_pc);
    let source_index = match src {
        VReg::Arch(ArchReg::X86(reg)) => reg.gpr_index(),
        _ => None,
    };
    let minimum_len = if source_index.is_some_and(|index| index >= 16) {
        4
    } else {
        3
    };
    instruction_len.is_some_and(|length| (minimum_len..=15).contains(&length))
        && op.x86_hint.is_none()
        && source_index.is_some_and(|index| index < 32)
        && matches!(
            control,
            X86ControlReg::Cr0
                | X86ControlReg::Cr2
                | X86ControlReg::Cr3
                | X86ControlReg::Cr4
                | X86ControlReg::Cr8
        )
}

impl X86_64Lowerer {
    /// Validate and commit MOV-to-CR through the emulator's canonical helper.
    ///
    /// Both outcomes leave the native region immediately. A failed validation
    /// restores every GPR and RFLAGS bit and restarts at `guest_pc`, allowing
    /// the direct path to deliver the precise architectural fault. Success
    /// resumes at `next_pc`; CR0/CR2/CR3/CR4 execute a host CPUID barrier before
    /// that handoff, while CR8 is not architecturally serializing.
    pub(crate) fn emit_x86_write_control(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "X86WriteControl requires JIT fault-deoptimization guards".to_string(),
            });
        }
        if !x86_write_control_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86WriteControl".to_string(),
                operand: "requires one x86 GPR, CR0/2/3/4/8, and an exact next PC".to_string(),
            });
        }
        let OpKind::X86WriteControl {
            src,
            control,
            next_pc,
        } = &op.kind
        else {
            unreachable!("validated X86WriteControl shape changed")
        };
        let source = match src {
            VReg::Arch(ArchReg::X86(reg)) => reg.gpr_index().unwrap(),
            _ => unreachable!("validated X86WriteControl source changed"),
        };
        let selector = match control {
            X86ControlReg::Cr0 => 0,
            X86ControlReg::Cr2 => 2,
            X86ControlReg::Cr3 => 3,
            X86ControlReg::Cr4 => 4,
            X86ControlReg::Cr8 => 8,
        };

        // Publish every identity-mapped GPR before crossing the Rust ABI.
        // Guest RSP/RBP are already authoritative in their state-backed slots.
        self.code.emit_u8(0x50); // push guest RAX
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq; helper call remains 16-byte aligned
        self.emit_spill_legacy_gprs_to_state_from_rax(8);
        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_system_helpers);

        // SysV arguments: RDI=GuestRegs, RSI=control selector, RDX=source.
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rdi, PhysReg::Rax, OpWidth::W64);
            emitter.emit_mov_ri(PhysReg::Rsi, selector, OpWidth::W32);
            emitter.emit_mov_rm(
                PhysReg::Rdx,
                PhysReg::Rax,
                i32::from(source) * 8,
                OpWidth::W64,
            );
        }
        // The SysV ABI requires DF=0 at an external Rust call boundary. The
        // saved guest RFLAGS image is restored byte-exactly on both exits.
        self.code.emit_u8(0xFC); // cld
        self.emit_host_c_helper_call(X86_GUEST_CONTROL_WRITE_FN_OFFSET as u32);

        self.code.emit_bytes(&[0x48, 0x8B, 0x4D]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        self.code.emit_bytes(&[0x48, 0x85, 0xC0]); // test rax,rax
        let fault = self.emit_jcc_placeholder(X86Cond::E);

        if !matches!(control, X86ControlReg::Cr8) {
            self.emit_x86_serialize();
        }
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq
        self.emit_flag_preserving_stack_pop8(); // discard saved pre-write RAX
        self.emit_x86_retirement();
        self.emit_native_exit(*next_pc);

        // The helper is non-committing on failure. Restore native register
        // files before returning to direct replay at the faulting instruction.
        self.patch_rel32_to_current(fault)?;
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq
        self.emit_flag_preserving_stack_pop8();
        self.emit_native_exit(op.guest_pc);
        Ok(())
    }
}

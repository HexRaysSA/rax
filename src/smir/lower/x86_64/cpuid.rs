//! Deterministic guest-CPUID helper lowering.

use super::X86_64Lowerer;
use crate::smir::ir::ops::{OpKind, SmirOp};
use crate::smir::ir::types::{ArchReg, VReg, X86Reg};
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::{LowerError, X86_GUEST_CPUID_FN_OFFSET, X86_STATE_PTR_AT_RBP};

/// The x86 encoding fixes both CPUID inputs and all four destinations. Keeping
/// the check shared between admission and lowering makes malformed hand-built
/// IR fail closed before it can alias the helper's state slots.
pub(crate) fn x86_cpuid_shape_valid(op: &OpKind) -> bool {
    matches!(
        op,
        OpKind::X86Cpuid {
            dst_eax: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
            dst_ebx: VReg::Arch(ArchReg::X86(X86Reg::Rbx)),
            dst_ecx: VReg::Arch(ArchReg::X86(X86Reg::Rcx)),
            dst_edx: VReg::Arch(ArchReg::X86(X86Reg::Rdx)),
            leaf: VReg::Arch(ArchReg::X86(X86Reg::Rax)),
            subleaf: VReg::Arch(ArchReg::X86(X86Reg::Rcx)),
        }
    )
}

impl X86_64Lowerer {
    pub fn set_preserve_vector_system_helpers(&mut self, on: bool) {
        self.preserve_vector_system_helpers = on;
    }

    pub(crate) fn emit_x86_cpuid(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !x86_cpuid_shape_valid(&op.kind) {
            return Err(LowerError::InvalidOperand {
                op: "X86Cpuid".to_string(),
                operand: "requires EAX/ECX inputs and EAX/EBX/ECX/EDX destinations".to_string(),
            });
        }

        // Publish every caller-saved guest GPR before crossing the Rust ABI.
        // The old guest RAX remains eight bytes above the saved flags so the
        // common spill routine can recover it after RAX becomes the state base.
        self.code.emit_u8(0x50); // push rax
        self.emit_load_state_ptr_rax();
        self.code.emit_u8(0x9C); // pushfq; stack remains 16-byte aligned
        self.emit_spill_legacy_gprs_to_state_from_rax(8);
        self.emit_helper_call_state(PhysReg::Rax, true, self.preserve_vector_system_helpers);

        self.code.emit_bytes(&[0x48, 0x89, 0xC7]); // mov rdi,rax (GuestRegs)
        self.emit_host_c_helper_call(X86_GUEST_CPUID_FN_OFFSET as u32);

        // The helper computes only guest-profile data. Execute a fixed host
        // leaf solely as the architectural serialization barrier; its outputs
        // are discarded when the helper-produced GuestRegs state is reloaded.
        self.code.emit_u8(0xB8); // mov eax,0 (flag-neutral)
        self.code.emit_u32(0);
        self.code.emit_bytes(&[0x0F, 0xA2]); // host CPUID serializing barrier

        self.code.emit_u8(0x48);
        self.code.emit_u8(0x8B);
        self.code.emit_u8(0x4D);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8); // mov rcx,[rbp+state_ptr]
        self.emit_helper_call_state(PhysReg::Rcx, false, self.preserve_vector_system_helpers);
        self.emit_reload_all(PhysReg::Rcx);
        self.code.emit_u8(0x9D); // popfq
        self.emit_flag_preserving_stack_pop8(); // discard saved pre-CPUID RAX
        Ok(())
    }
}

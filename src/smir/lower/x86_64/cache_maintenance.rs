//! Fault-precise cache maintenance without executing privileged host opcodes.

use super::{X86_64Lowerer, X86Cond};
use crate::smir::ir::ops::{OpKind, SmirOp, X86CacheMaintenanceKind};
use crate::smir::lower::{
    LowerError, X86_GUEST_CPL_OFFSET, X86_GUEST_CR0_OFFSET, X86_STATE_PTR_AT_RBP,
};

pub(crate) fn x86_cache_maintenance_shape_valid(op: &SmirOp) -> bool {
    let OpKind::X86CacheMaintenance { kind, next_pc } = op.kind else {
        return false;
    };
    let minimum = if kind == X86CacheMaintenanceKind::Wbnoinvd {
        3
    } else {
        2
    };
    next_pc > op.guest_pc && (minimum..=15).contains(&(next_pc - op.guest_pc))
}

impl X86_64Lowerer {
    pub(crate) fn emit_x86_cache_maintenance(&mut self, op: &SmirOp) -> Result<(), LowerError> {
        if !self.jit_fault_deopt_guards {
            return Err(LowerError::UnsupportedOp {
                op: "cache maintenance requires precise fault guards".into(),
            });
        }
        if !x86_cache_maintenance_shape_valid(op) {
            return Err(LowerError::InvalidOperand {
                op: "X86CacheMaintenance".into(),
                operand: "requires a valid kind and exact next instruction PC".into(),
            });
        }
        let OpKind::X86CacheMaintenance { next_pc, .. } = op.kind else {
            unreachable!()
        };
        self.code.emit_u8(0x9c); // PUSHFQ
        self.code.emit_u8(0x50); // PUSH RAX
        self.code.emit_bytes(&[0x48, 0x8b, 0x45]);
        self.code.emit_u8(X86_STATE_PTR_AT_RBP as u8);
        self.code.emit_bytes(&[0xf7, 0x80]); // TEST dword [RAX+CR0],1
        self.code.emit_u32(X86_GUEST_CR0_OFFSET as u32);
        self.code.emit_u32(1);
        let real_mode = self.emit_jcc_placeholder(X86Cond::E);
        self.code.emit_bytes(&[0x48, 0x83, 0xb8]); // CMP qword [RAX+CPL],0
        self.code.emit_u32(X86_GUEST_CPL_OFFSET as u32);
        self.code.emit_u8(0);
        let denied = self.emit_jcc_placeholder(X86Cond::Ne);
        self.patch_rel32_to_current(real_mode)?;
        self.code.emit_u8(0x58);
        self.code.emit_u8(0x9d);
        self.code.emit_bytes(&[0x0f, 0xae, 0xf0]); // MFENCE: no host cache invalidation
        // End the native slice so prior code writes are drained before the
        // next guest instruction is fetched or another cached region runs.
        self.emit_x86_retirement();
        self.emit_native_exit(next_pc);
        self.patch_rel32_to_current(denied)?;
        self.code.emit_u8(0x58);
        self.code.emit_u8(0x9d);
        self.emit_native_exit(op.guest_pc);
        Ok(())
    }
}

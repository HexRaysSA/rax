//! Exact scalar W64 immediates, including constants produced by optimization.
//!
//! Group 1 and TEST sign-extend their encoded imm32. A semantic 64-bit
//! immediate outside that range therefore needs a register source, not a
//! truncating RI encoding. Temporary host registers are saved and restored;
//! architectural RSP/RBP and APX EGPRs use coherent GuestRegs slots.

use crate::smir::ir::flags::FlagUpdate;
use crate::smir::ir::ops::{OpKind, SmirOp, X86AluEncoding, X86OpHint};
use crate::smir::ir::types::{ArchReg, OpWidth, VReg};
use crate::smir::lower::LowerError;
use crate::smir::lower::regalloc::PhysReg;
use crate::smir::lower::x86_64::{X86_64Lowerer, X86Emitter};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum X86ScalarAluKind {
    Add,
    Or,
    Adc,
    Sbb,
    And,
    Sub,
    Xor,
    Cmp,
    Test,
}

impl X86ScalarAluKind {
    fn digit(self) -> Option<u8> {
        Some(match self {
            Self::Add => 0,
            Self::Or => 1,
            Self::Adc => 2,
            Self::Sbb => 3,
            Self::And => 4,
            Self::Sub => 5,
            Self::Xor => 6,
            Self::Cmp => 7,
            Self::Test => return None,
        })
    }

    fn emit_register(
        self,
        emitter: &mut X86Emitter<'_>,
        lhs: PhysReg,
        rhs: PhysReg,
        width: OpWidth,
    ) {
        if let Some(digit) = self.digit() {
            emitter.emit_alu_rr(digit * 8, lhs, rhs, width);
        } else {
            emitter.emit_test_rr(lhs, rhs, width);
        }
    }

    /// Caller proves that an imm32 sign extension represents the W64 value.
    fn emit_encodable_immediate(
        self,
        emitter: &mut X86Emitter<'_>,
        lhs: PhysReg,
        value: i64,
        width: OpWidth,
        hint: Option<X86AluEncoding>,
    ) {
        debug_assert!(scalar_alu_immediate_is_encodable(value, width));
        if let Some(digit) = self.digit() {
            if hint == Some(X86AluEncoding::AccImm) && lhs == PhysReg::Rax {
                emitter.emit_alu_acc_imm(digit * 8 + 4, value, width);
            } else {
                emitter.emit_alu_ri(digit, lhs, value, width);
            }
        } else {
            emitter.emit_test_ri(lhs, value, width);
        }
    }
}

pub(crate) fn scalar_alu_immediate_is_encodable(value: i64, width: OpWidth) -> bool {
    width != OpWidth::W64 || i32::try_from(value).is_ok()
}

#[derive(Clone, Copy)]
pub(crate) struct X86ScalarAluImmediate {
    pub(crate) kind: X86ScalarAluKind,
    pub(crate) dst: Option<VReg>,
    pub(crate) src1: VReg,
    pub(crate) value: i64,
    pub(crate) flags: FlagUpdate,
}

fn decode_immediate(kind: &OpKind) -> Option<X86ScalarAluImmediate> {
    let (kind, dst, src1, source, width, flags) = match kind {
        OpKind::Add {
            dst,
            src1,
            src2,
            width,
            flags,
        } => (
            X86ScalarAluKind::Add,
            Some(*dst),
            *src1,
            src2,
            *width,
            *flags,
        ),
        OpKind::Or {
            dst,
            src1,
            src2,
            width,
            flags,
        } => (
            X86ScalarAluKind::Or,
            Some(*dst),
            *src1,
            src2,
            *width,
            *flags,
        ),
        OpKind::Adc {
            dst,
            src1,
            src2,
            width,
            flags,
        } => (
            X86ScalarAluKind::Adc,
            Some(*dst),
            *src1,
            src2,
            *width,
            *flags,
        ),
        OpKind::Sbb {
            dst,
            src1,
            src2,
            width,
            flags,
        } => (
            X86ScalarAluKind::Sbb,
            Some(*dst),
            *src1,
            src2,
            *width,
            *flags,
        ),
        OpKind::And {
            dst,
            src1,
            src2,
            width,
            flags,
        } => (
            X86ScalarAluKind::And,
            Some(*dst),
            *src1,
            src2,
            *width,
            *flags,
        ),
        OpKind::Sub {
            dst,
            src1,
            src2,
            width,
            flags,
        } => (
            X86ScalarAluKind::Sub,
            Some(*dst),
            *src1,
            src2,
            *width,
            *flags,
        ),
        OpKind::Xor {
            dst,
            src1,
            src2,
            width,
            flags,
        } => (
            X86ScalarAluKind::Xor,
            Some(*dst),
            *src1,
            src2,
            *width,
            *flags,
        ),
        OpKind::Cmp { src1, src2, width } => (
            X86ScalarAluKind::Cmp,
            None,
            *src1,
            src2,
            *width,
            FlagUpdate::All,
        ),
        OpKind::Test { src1, src2, width } => (
            X86ScalarAluKind::Test,
            None,
            *src1,
            src2,
            *width,
            FlagUpdate::All,
        ),
        _ => return None,
    };
    if width != OpWidth::W64 {
        return None;
    }
    Some(X86ScalarAluImmediate {
        kind,
        dst,
        src1,
        value: source.as_imm()?,
        flags,
    })
}

fn shape_valid(op: &SmirOp, shape: X86ScalarAluImmediate) -> bool {
    matches!(op.x86_hint, None | Some(X86OpHint::AluEncoding(_)))
        && matches!(shape.flags, FlagUpdate::None | FlagUpdate::All)
}

pub(crate) fn x86_scalar_alu_immediate_candidate(op: &SmirOp) -> bool {
    decode_immediate(&op.kind).is_some()
}

pub(crate) fn x86_scalar_alu_immediate_shape(op: &SmirOp) -> Option<X86ScalarAluImmediate> {
    decode_immediate(&op.kind).filter(|shape| shape_valid(op, *shape))
}

/// Exact native admission predicate. The generic lowerer also handles
/// allocated virtual registers, but the identity-mapped guest JIT must not
/// admit them as standalone architectural operands.
pub(crate) fn x86_scalar_alu_immediate_valid(op: &SmirOp) -> bool {
    let Some(shape) = decode_immediate(&op.kind) else {
        return false;
    };
    let gpr = |reg: VReg| matches!(reg, VReg::Arch(ArchReg::X86(reg)) if reg.gpr_index().is_some());
    shape_valid(op, shape) && gpr(shape.src1) && shape.dst.is_none_or(gpr)
}

impl X86_64Lowerer {
    /// Emit one ALU operation after its LHS has been placed in `lhs`.
    /// Surrounding code owns flag suppression. Saving/materializing/restoring
    /// the scratch itself changes no flags and therefore preserves ADC/SBB CF.
    pub(crate) fn emit_scalar_alu_immediate(
        &mut self,
        kind: X86ScalarAluKind,
        lhs: PhysReg,
        value: i64,
        width: OpWidth,
        hint: Option<X86AluEncoding>,
        excluded: &[PhysReg],
    ) -> Result<(), LowerError> {
        if !matches!(
            width,
            OpWidth::W8 | OpWidth::W16 | OpWidth::W32 | OpWidth::W64
        ) || !PhysReg::ALLOCATABLE.contains(&lhs)
        {
            return Err(LowerError::InvalidOperand {
                op: "scalar ALU immediate".to_string(),
                operand: format!("invalid scalar carrier {lhs:?} or width {width:?}"),
            });
        }
        if scalar_alu_immediate_is_encodable(value, width) {
            let mut emitter = X86Emitter::new(&mut self.code);
            kind.emit_encodable_immediate(&mut emitter, lhs, value, width, hint);
            return Ok(());
        }

        // At most the two explicit scalar operands are excluded. Saving a
        // mapped scratch keeps every other guest GPR intact even with no free
        // register in the identity map. RSP/RBP never participate as scratch.
        let scratch = [PhysReg::R11, PhysReg::R10, PhysReg::R9]
            .into_iter()
            .find(|candidate| *candidate != lhs && !excluded.contains(candidate))
            .ok_or_else(|| LowerError::RegisterAllocationFailed {
                reason: "no nonaliasing scalar immediate scratch".to_string(),
            })?;
        let mut emitter = X86Emitter::new(&mut self.code);
        emitter.emit_push(scratch);
        emitter.emit_mov_ri_imm64(scratch, value);
        kind.emit_register(&mut emitter, lhs, scratch, width);
        emitter.emit_pop(scratch);
        Ok(())
    }

    /// Handle all W64 immediate forms before a generic RI arm can truncate
    /// them. Malformed candidates return an error, never a partial fallback.
    pub(crate) fn try_lower_scalar_alu_immediate(
        &mut self,
        op: &SmirOp,
    ) -> Result<bool, LowerError> {
        let Some(shape) = decode_immediate(&op.kind) else {
            return Ok(false);
        };
        if !shape_valid(op, shape) {
            return Err(LowerError::InvalidOperand {
                op: "W64 scalar ALU immediate".to_string(),
                operand: format!("unsupported flags or encoding hint: {op:?}"),
            });
        }
        if Self::x86_state_backed_gpr(shape.src1)
            || shape.dst.is_some_and(Self::x86_state_backed_gpr)
        {
            if !x86_scalar_alu_immediate_valid(op) {
                return Err(LowerError::InvalidOperand {
                    op: "state-backed W64 scalar ALU immediate".to_string(),
                    operand: "all scalar operands must be architectural x86 GPRs".to_string(),
                });
            }
            self.lower_state_scalar_alu_immediate(shape)?;
            return Ok(true);
        }
        let source = self.get_reg(shape.src1)?;
        let lhs = if let Some(destination) = shape.dst {
            self.get_dst_reg(destination)?
        } else {
            source
        };
        Self::ensure_flag_stack_operands_safe("W64 scalar ALU immediate", &[source, lhs])?;
        if !PhysReg::ALLOCATABLE.contains(&source) || !PhysReg::ALLOCATABLE.contains(&lhs) {
            return Err(LowerError::InvalidOperand {
                op: "W64 scalar ALU immediate".to_string(),
                operand: "non-GPR physical operand".to_string(),
            });
        }
        let preserve_flags = shape.flags == FlagUpdate::None;
        if preserve_flags {
            self.code.emit_u8(0x9C); // pushfq; ADC/SBB still consume incoming CF
        }
        if lhs != source {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(lhs, source, OpWidth::W64);
        }
        let hint = match op.x86_hint {
            Some(X86OpHint::AluEncoding(hint)) => Some(hint),
            _ => None,
        };
        self.emit_scalar_alu_immediate(
            shape.kind,
            lhs,
            shape.value,
            OpWidth::W64,
            hint,
            &[source],
        )?;
        if preserve_flags {
            self.code.emit_u8(0x9D); // popfq
        }
        Ok(true)
    }

    fn lower_state_scalar_alu_immediate(
        &mut self,
        shape: X86ScalarAluImmediate,
    ) -> Result<(), LowerError> {
        let invalid = || LowerError::InvalidOperand {
            op: "state-backed W64 scalar ALU immediate".to_string(),
            operand: "operand is not an architectural x86 GPR".to_string(),
        };
        let source_index = Self::x86_gpr_index(shape.src1).ok_or_else(invalid)?;
        let destination_index = match shape.dst {
            Some(destination) => Some(Self::x86_gpr_index(destination).ok_or_else(invalid)?),
            None => None,
        };

        self.code.emit_u8(0x50); // preserve guest RAX for coherent snapshot
        self.emit_load_state_ptr_rax();
        let preserve_flags = shape.flags == FlagUpdate::None;
        if preserve_flags {
            self.code.emit_u8(0x9C); // pushfq; saved guest RAX is now at +8
        }
        self.emit_spill_legacy_gprs_to_state_from_rax(if preserve_flags { 8 } else { 0 });
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rm(
                PhysReg::Rdx,
                PhysReg::Rax,
                i32::from(source_index) * 8,
                OpWidth::W64,
            );
            if scalar_alu_immediate_is_encodable(shape.value, OpWidth::W64) {
                shape.kind.emit_encodable_immediate(
                    &mut emitter,
                    PhysReg::Rdx,
                    shape.value,
                    OpWidth::W64,
                    None,
                );
            } else {
                emitter.emit_mov_ri_imm64(PhysReg::Rdi, shape.value);
                shape
                    .kind
                    .emit_register(&mut emitter, PhysReg::Rdx, PhysReg::Rdi, OpWidth::W64);
            }
        }
        if let Some(destination_index) = destination_index {
            self.emit_store_gpr_slot_from_reg(destination_index, PhysReg::Rdx, OpWidth::W64)?;
            if destination_index == 5 {
                let mut emitter = X86Emitter::new(&mut self.code);
                emitter.emit_mov_mr(PhysReg::Rbp, 0, PhysReg::Rdx, OpWidth::W64);
            }
        }
        {
            let mut emitter = X86Emitter::new(&mut self.code);
            emitter.emit_mov_rr(PhysReg::Rcx, PhysReg::Rax, OpWidth::W64);
        }
        self.emit_reload_all(PhysReg::Rcx);
        if preserve_flags {
            self.code.emit_u8(0x9D); // popfq
        }
        self.emit_flag_preserving_stack_pop8();
        Ok(())
    }
}

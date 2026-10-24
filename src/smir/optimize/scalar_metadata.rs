//! Scalar ALU register operands and status-flag metadata.

use crate::smir::ir::flags::{FlagSet, FlagState, FlagUpdate};
use crate::smir::ir::ops::{
    OpKind, X86AdxKind, X86RepMode, X86StringKind, X86WaitPkgOp, X86X87DataKind,
};
use crate::smir::ir::types::{ArchReg, ArmReg, SrcOperand, VReg};

/// Include the register read by a shifted or extended operand before native
/// clobber checks and liveness analysis consume the scalar source list.
pub(super) fn scalar_alu_sources(src1: VReg, src2: &SrcOperand) -> Vec<VReg> {
    let mut sources = vec![src1];
    match src2 {
        SrcOperand::Reg(reg)
        | SrcOperand::Shifted { reg, .. }
        | SrcOperand::Extended { reg, .. } => sources.push(*reg),
        SrcOperand::Imm(_) | SrcOperand::Imm64(_) => {}
    }
    sources
}

impl OpKind {
    /// Get mutable reference to flag update field
    pub fn flags_written_mut(&mut self) -> Option<&mut FlagUpdate> {
        match self {
            OpKind::Add { flags, .. }
            | OpKind::X86Xadd(crate::smir::ir::ops::X86XaddOp { flags, .. })
            | OpKind::X86Cmpxchg(crate::smir::ir::ops::X86CmpxchgOp { flags, .. })
            | OpKind::Sub { flags, .. }
            | OpKind::Adc { flags, .. }
            | OpKind::Sbb { flags, .. }
            | OpKind::Neg { flags, .. }
            | OpKind::Inc { flags, .. }
            | OpKind::Dec { flags, .. }
            | OpKind::And { flags, .. }
            | OpKind::Or { flags, .. }
            | OpKind::Xor { flags, .. }
            | OpKind::AndNot { flags, .. }
            | OpKind::Shl { flags, .. }
            | OpKind::Shr { flags, .. }
            | OpKind::Sar { flags, .. }
            | OpKind::Shld { flags, .. }
            | OpKind::Shrd { flags, .. }
            | OpKind::X86NddDoubleShift { flags, .. }
            | OpKind::Rol { flags, .. }
            | OpKind::Ror { flags, .. }
            | OpKind::ArmRegShift { flags, .. }
            | OpKind::ArmDpRegShift { flags, .. }
            | OpKind::Rcl { flags, .. }
            | OpKind::Rcr { flags, .. }
            | OpKind::Bsf { flags, .. }
            | OpKind::Bsr { flags, .. }
            | OpKind::X86Count { flags, .. }
            | OpKind::Bextr { flags, .. }
            | OpKind::Bzhi { flags, .. }
            | OpKind::X86Bls { flags, .. }
            | OpKind::X86Tbm { flags, .. }
            | OpKind::X86Adx { flags, .. }
            | OpKind::MulU { flags, .. }
            | OpKind::MulS { flags, .. } => Some(flags),
            _ => None,
        }
    }

    /// Get the flags written by this operation (the flags it may define).
    pub fn flags_written(&self) -> FlagSet {
        match self {
            OpKind::ArmPauth(operation) if matches!(operation.instruction,
                crate::isa::arm::aarch64::pauth_instruction::PauthInstruction::ExceptionReturn { .. }) => FlagSet::NZCV,

            OpKind::Add { flags, .. }
            | OpKind::X86Xadd(crate::smir::ir::ops::X86XaddOp { flags, .. })
            | OpKind::X86Cmpxchg(crate::smir::ir::ops::X86CmpxchgOp { flags, .. })
            | OpKind::Sub { flags, .. }
            | OpKind::Adc { flags, .. }
            | OpKind::Sbb { flags, .. }
            | OpKind::Neg { flags, .. }
            | OpKind::And { flags, .. }
            | OpKind::Or { flags, .. }
            | OpKind::Xor { flags, .. }
            | OpKind::AndNot { flags, .. }
            | OpKind::Shl { flags, .. }
            | OpKind::Shr { flags, .. }
            | OpKind::Sar { flags, .. }
            | OpKind::ArmRegShift { flags, .. }
            | OpKind::ArmDpRegShift { flags, .. }
            | OpKind::Shld { flags, .. }
            | OpKind::Shrd { flags, .. }
            | OpKind::X86NddDoubleShift { flags, .. }
            | OpKind::Bsf { flags, .. }
            | OpKind::Bsr { flags, .. }
            | OpKind::X86Count { flags, .. }
            | OpKind::Bextr { flags, .. }
            | OpKind::Bzhi { flags, .. }
            | OpKind::X86Bls { flags, .. }
            | OpKind::X86Tbm { flags, .. }
            | OpKind::X86Adx { flags, .. }
            | OpKind::MulU { flags, .. }
            | OpKind::MulS { flags, .. } => flags.as_set(),

            OpKind::Rol { flags, .. }
            | OpKind::Ror { flags, .. }
            | OpKind::Rcl { flags, .. }
            | OpKind::Rcr { flags, .. } => {
                flags.as_set().intersection(FlagSet::CF.union(FlagSet::OF))
            }

            // INC/DEC update OF/SF/ZF/AF/PF but PRESERVE CF (their defining
            // difference from ADD/SUB by 1). Never report CF as written.
            OpKind::Inc { flags, .. } | OpKind::Dec { flags, .. } => {
                flags.as_set().difference(FlagSet::CF)
            }

            // Flag-only scalar ALU operations use the corresponding full
            // arithmetic flag contract; architectural state exports NZCV on ARM.
            OpKind::Cmp { .. }
            | OpKind::Cmn { .. }
            | OpKind::Test { .. }
            | OpKind::AtomicCmpXadd { .. } => FlagSet::ALL_X86,

            OpKind::X86FpCompare { .. } => FlagSet::ALL_X86,

            OpKind::X86PackedStringCompare { .. } => FlagSet::ALL_X86,

            OpKind::X86Opmask(op) if op.is_test() => FlagSet::ALL_X86,

            OpKind::X86Cmpxchg8b16b { .. } => FlagSet::ZF,

            OpKind::X86SelectorVerify(..) | OpKind::X86SelectorQuery(..) => FlagSet::ZF,

            OpKind::X86Random { .. } => FlagSet::ALL_X86,

            OpKind::X86WaitPkg(X86WaitPkgOp::Umwait { .. } | X86WaitPkgOp::Tpause { .. }) => {
                FlagSet::ALL_X86
            }

            OpKind::X86StackFlags(crate::smir::ir::ops::X86StackFlagsOp {
                kind: crate::smir::ir::ops::X86StackFlagsKind::Pop,
                ..
            }) => FlagSet::ALL_X86,

            OpKind::X86XTest => FlagSet::ALL_X86,

            OpKind::X86X87Data {
                kind: X86X87DataKind::Compare { eflags: true, .. },
                ..
            } => FlagSet::ALL_X86,

            // Every register bit-test form updates CF.
            OpKind::Bt { .. } | OpKind::Bts { .. } | OpKind::Btr { .. } | OpKind::Btc { .. } => {
                FlagSet::CF
            }

            // SCAS and CMPS may update all arithmetic flags. With REP, an
            // initial count of zero performs no comparison and preserves them.
            OpKind::X86String {
                kind: X86StringKind::Scas | X86StringKind::Cmps,
                ..
            } => FlagSet::ALL_X86,

            OpKind::SetCF { .. } | OpKind::CmcCF => FlagSet::CF,

            _ => FlagSet::EMPTY,
        }
    }

    /// Flags this op DEFINITELY writes a defined value to, regardless of its
    /// operands — the set safe to treat as "killed" (overwritten) in backward
    /// flag-liveness. Conservatively smaller than `flags_written` for ops whose
    /// flag effect is operand-conditional or partly undefined: a shift/rotate
    /// by a variable count writes nothing when the count is 0, and MUL/IMUL and
    /// BSF/BSR leave most flags undefined. Using a smaller must-write set can
    /// only keep more upstream flags live (safe), never delete a needed one.
    pub fn flags_must_write(&self) -> FlagSet {
        match self {
            OpKind::ArmPauth(..) => FlagSet::EMPTY,

            OpKind::Shl { .. }
            | OpKind::Shr { .. }
            | OpKind::Sar { .. }
            | OpKind::Shld { .. }
            | OpKind::Shrd { .. }
            | OpKind::X86NddDoubleShift { .. }
            | OpKind::Rol { .. }
            | OpKind::Ror { .. }
            | OpKind::Rcl { .. }
            | OpKind::Rcr { .. }
            | OpKind::MulU { .. }
            | OpKind::MulS { .. }
            | OpKind::Bsf { .. }
            | OpKind::Bsr { .. } => FlagSet::EMPTY,
            OpKind::X86String {
                kind: X86StringKind::Scas | X86StringKind::Cmps,
                rep,
                ..
            } if *rep != X86RepMode::None => FlagSet::EMPTY,
            // POPF can fault before or after its stack read. Incoming flags
            // remain architectural on either exit, so it cannot kill their
            // liveness even though every successful form writes status flags.
            OpKind::X86StackFlags(crate::smir::ir::ops::X86StackFlagsOp {
                kind: crate::smir::ir::ops::X86StackFlagsKind::Pop,
                ..
            }) => FlagSet::EMPTY,
            OpKind::X86X87Data {
                kind: X86X87DataKind::Compare { eflags: true, .. },
                ..
            } => FlagSet::OF.union(FlagSet::SF).union(FlagSet::AF),
            _ => self.flags_written(),
        }
    }

    /// Get the flags read by this operation
    pub fn flags_read(&self) -> FlagSet {
        match self {
            OpKind::ArmInstructionBegin { .. }
            | OpKind::ArmInstructionCommit { .. }
            | OpKind::ArmPauth(..) => FlagSet::NZCV,

            // Add/Sub with carry read CF
            OpKind::Adc { .. } | OpKind::Sbb { .. } | OpKind::Rcl { .. } | OpKind::Rcr { .. } => {
                FlagSet::CF
            }

            // A zero low-byte count preserves C only when C is among the
            // requested architectural outputs. Flagless T32 forms and
            // dead-flag-eliminated shifts do not consume the incoming carry.
            OpKind::ArmRegShift { flags, .. } => {
                if flags.as_set().contains(FlagSet::CF) {
                    FlagSet::CF
                } else {
                    FlagSet::EMPTY
                }
            }

            OpKind::ArmDpRegShift { kind, flags, .. } => {
                if kind.reads_carry() || (kind.is_logical() && flags.as_set().contains(FlagSet::CF))
                {
                    FlagSet::CF
                } else {
                    FlagSet::EMPTY
                }
            }

            OpKind::X86Adx { kind, .. } => match kind {
                X86AdxKind::Adcx => FlagSet::CF,
                X86AdxKind::Adox => FlagSet::OF,
            },

            // Conditional move reads flags based on condition
            OpKind::CMove { cond, .. } | OpKind::SetCC { cond, .. } => {
                FlagState::required_flags(*cond)
            }

            // TestCondition reads flags
            OpKind::TestCondition { cond, .. } => FlagState::required_flags(*cond),

            OpKind::X86X87Data {
                kind: X86X87DataKind::ConditionalMove(cond),
                ..
            } => FlagState::required_flags(*cond),

            // AArch64 conditional-compare lifting materializes ArmReg::Nzcv
            // from the immediately preceding flag-producing compare op.
            OpKind::Mov {
                src: SrcOperand::Reg(VReg::Arch(ArchReg::Arm(ArmReg::Nzcv))),
                ..
            } => FlagSet::NZCV,

            // Complement carry reads CF
            OpKind::CmcCF => FlagSet::CF,

            // ReadFlags reads all flags
            OpKind::ReadFlags { .. } => FlagSet::ALL_X86,

            // PUSHF consumes the current image. POPF also consumes it for its
            // precise pre/post-memory fault state and privilege-preserved bits.
            OpKind::X86StackFlags(..) => FlagSet::ALL_X86,

            _ => FlagSet::EMPTY,
        }
    }
}

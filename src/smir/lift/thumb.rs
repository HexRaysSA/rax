//! Thumb (T16) and Thumb-2 (T32) scalar instruction lifter.
//!
//! This lifter shares scalar operation construction with the AArch64 lifter,
//! but enforces the architectural boundaries that are specific to AArch32
//! Thumb execution:
//!
//! - r13 and r14 are identity-mapped AArch32 GPRs (`X13`/`X14`), not the
//!   AArch64 SP/LR aliases;
//! - r15 data-register operands, IT-state predication, predicated data
//!   instructions and RRX fail closed; T16 move/logical/multiply/shift forms
//!   use selective NZCV contracts so architecturally preserved flags remain
//!   unchanged; T16 and T32 register-controlled shifts use exact low-byte
//!   counts and admit independent T32 destination/value/count registers;
//! - unconditional and explicit condition-code Thumb branches use the
//!   architectural `PC + 4` base and become explicit SMIR control-flow edges;
//!   CBZ/CBNZ become explicit register-conditioned edges, BL writes
//!   `(next_pc | 1)` to r14, BX becomes a gated interworking dispatcher exit,
//!   BLX preserves the Thumb return-state bit while exporting the ARM/register
//!   target state, and all PC arithmetic wraps modulo 2^32;
//! - T16/T32 scalar single- and multiple-transfer memory uses the W32 helper
//!   contract; literal loads freeze `Align(PC + 4, 4)` into absolute-address
//!   IR, while other PC-bearing, empty-list, and constrained base/list forms
//!   fail closed;
//! - T32 LDRD/STRD over validated adjacent even register pairs retain atomic
//!   load-destination and ordered-store fault behavior through pair memory IR;
//! - T32 MOVT and bitfield encodings are translated using their T32 layouts;
//! - both 16-bit and 32-bit instruction lengths are retained by block lifting.

use std::collections::HashSet;

use crate::isa::arm::ExecutionState;
use crate::isa::arm::decoder::{
    AddressingMode, Condition as ArmCondition, DecodedInsn, Decoder, MemOffset, MemOperand,
    Mnemonic, Operand, Register, ShiftType, ThumbDecoder,
};
use crate::smir::ir::flags::{FlagSet, FlagUpdate};
use crate::smir::ir::ops::{OpKind, SmirOp};
use crate::smir::ir::types::{
    Address, ArchReg, ArmReg, Condition, DispSize, FunctionId, GuestAddr, MemWidth, OpId, OpWidth,
    SignExtend, SourceArch, SrcOperand, VReg,
};
use crate::smir::ir::{
    CallTarget, CallingConv, FunctionAttrs, SmirBlock, SmirFunction, Terminator, TrapKind,
};
use crate::smir::lift::aarch64::Aarch64Lifter;
use crate::smir::lift::{
    ControlFlow, LiftContext, LiftError, LiftResult, MemoryReader, SmirLifter,
};

/// Fail-closed T16/T32 scalar lifter.
pub struct ThumbLifter {
    shared: Aarch64Lifter,
}

impl ThumbLifter {
    pub fn new() -> Self {
        Self {
            shared: Aarch64Lifter::strict(),
        }
    }

    #[inline]
    fn reg(num: u8) -> VReg {
        VReg::Arch(ArchReg::Arm(ArmReg::X(num)))
    }

    fn push(ops: &mut Vec<SmirOp>, pc: GuestAddr, kind: OpKind) {
        ops.push(SmirOp::new(OpId(ops.len() as u16), pc, kind));
    }

    fn pc32(pc: GuestAddr) -> Result<u32, LiftError> {
        u32::try_from(pc).map_err(|_| LiftError::Unsupported {
            addr: pc,
            mnemonic: "Thumb guest PC outside the 32-bit address space".to_string(),
        })
    }

    fn add_pc_offset(
        pc: GuestAddr,
        pipeline_bias: u32,
        offset: i64,
    ) -> Result<GuestAddr, LiftError> {
        let pc = Self::pc32(pc)?;
        Ok(u64::from(
            pc.wrapping_add(pipeline_bias).wrapping_add(offset as u32),
        ))
    }

    fn next_pc(pc: GuestAddr, bytes: usize) -> Result<GuestAddr, LiftError> {
        let bytes = u32::try_from(bytes)
            .map_err(|_| LiftError::Internal("Thumb instruction length exceeds u32".to_string()))?;
        Ok(u64::from(Self::pc32(pc)?.wrapping_add(bytes)))
    }

    /// The generic AArch64 lifter interprets `Register::is_sp` as architectural
    /// AArch64 SP. Thumb's r13 is instead identity-mapped to host X13.
    fn normalize_regs(insn: &DecodedInsn) -> DecodedInsn {
        let mut normalized = insn.clone();
        for operand in &mut normalized.operands {
            match operand {
                Operand::ShiftedReg(shifted)
                    if shifted.shift_type == ShiftType::LSL
                        && shifted.immediate_amount() == Some(0) =>
                {
                    let reg = shifted.reg;
                    *operand = Operand::Reg(if reg.num == 13 {
                        Register::raw(13, false, false)
                    } else {
                        reg
                    });
                }
                Operand::Reg(reg) if reg.num == 13 => {
                    *reg = Register::raw(13, false, false);
                }
                Operand::ShiftedReg(shifted) if shifted.reg.num == 13 => {
                    shifted.reg = Register::raw(13, false, false);
                }
                Operand::ExtendedReg(extended) if extended.reg.num == 13 => {
                    extended.reg = Register::raw(13, false, false);
                }
                _ => {}
            }
        }
        normalized
    }

    fn rejects_hidden_state(insn: &DecodedInsn) -> bool {
        // BCC carries an explicit condition but has no predicated data effects;
        // represent it as a two-edge SMIR terminator. IT and every other
        // condition-bearing instruction still need instruction-level gating.
        if (insn.cond.is_some() && insn.mnemonic != Mnemonic::BCC) || insn.mnemonic == Mnemonic::IT
        {
            return true;
        }
        insn.operands.iter().any(|operand| match operand {
            Operand::Reg(reg) => reg.num >= 15,
            Operand::ShiftedReg(shifted) => {
                shifted.reg.num >= 15
                    || shifted.shift_type == ShiftType::RRX
                    || !matches!(shifted.immediate_amount(), Some(amount) if amount < 32)
            }
            Operand::ExtendedReg(extended) => extended.reg.num >= 15,
            Operand::Mem(mem) => {
                mem.base.num >= 15
                    || match &mem.offset {
                        MemOffset::None | MemOffset::Imm(_) => false,
                        MemOffset::Reg(reg) => reg.num >= 15,
                        MemOffset::ShiftedReg(shifted) => {
                            shifted.reg.num >= 15
                                || shifted.shift_type != ShiftType::LSL
                                || !matches!(shifted.immediate_amount(), Some(amount) if amount <= 3)
                        }
                        MemOffset::ExtendedReg(_) => true,
                    }
            }
            Operand::RegList(_) => false,
            _ => false,
        })
    }

    fn branch_condition(cond: ArmCondition, pc: GuestAddr) -> Result<Condition, LiftError> {
        let cond = match cond {
            ArmCondition::EQ => Condition::Eq,
            ArmCondition::NE => Condition::Ne,
            ArmCondition::CS => Condition::Uge,
            ArmCondition::CC => Condition::Ult,
            ArmCondition::MI => Condition::Negative,
            ArmCondition::PL => Condition::Positive,
            ArmCondition::VS => Condition::Overflow,
            ArmCondition::VC => Condition::NoOverflow,
            ArmCondition::HI => Condition::Ugt,
            ArmCondition::LS => Condition::Ule,
            ArmCondition::GE => Condition::Sge,
            ArmCondition::LT => Condition::Slt,
            ArmCondition::GT => Condition::Sgt,
            ArmCondition::LE => Condition::Sle,
            ArmCondition::AL | ArmCondition::NV => {
                return Err(LiftError::Unsupported {
                    addr: pc,
                    mnemonic: "Thumb conditional branch uses reserved AL/NV condition".to_string(),
                });
            }
        };
        Ok(cond)
    }

    fn memory_kind(mnemonic: Mnemonic) -> Option<(bool, MemWidth, SignExtend)> {
        match mnemonic {
            Mnemonic::LDR => Some((true, MemWidth::B4, SignExtend::Zero)),
            Mnemonic::LDRB => Some((true, MemWidth::B1, SignExtend::Zero)),
            Mnemonic::LDRH => Some((true, MemWidth::B2, SignExtend::Zero)),
            Mnemonic::LDRSB => Some((true, MemWidth::B1, SignExtend::Sign)),
            Mnemonic::LDRSH => Some((true, MemWidth::B2, SignExtend::Sign)),
            Mnemonic::STR => Some((false, MemWidth::B4, SignExtend::Zero)),
            Mnemonic::STRB => Some((false, MemWidth::B1, SignExtend::Zero)),
            Mnemonic::STRH => Some((false, MemWidth::B2, SignExtend::Zero)),
            _ => None,
        }
    }

    fn literal_load(insn: &DecodedInsn, pc: GuestAddr) -> Result<Option<OpKind>, LiftError> {
        let Some((true, width, sign)) = Self::memory_kind(insn.mnemonic) else {
            return Ok(None);
        };
        let (rt, offset) = match insn.operands.as_slice() {
            [Operand::Reg(rt), Operand::Label(offset)]
                if insn.mnemonic == Mnemonic::LDR && insn.size == 2 =>
            {
                (rt, *offset)
            }
            [
                Operand::Reg(rt),
                Operand::Mem(MemOperand {
                    base,
                    offset: MemOffset::Imm(offset),
                    mode: AddressingMode::Offset,
                }),
            ] if base.num == 15 => (rt, *offset),
            _ => return Ok(None),
        };
        if rt.num >= 15 || insn.cond.is_some() {
            return Ok(None);
        }
        let base = Self::pc32(pc)?.wrapping_add(4) & !0x3;
        let address = base.wrapping_add(offset as u32);
        Ok(Some(OpKind::Load {
            dst: Self::reg(rt.num),
            addr: Address::Absolute(u64::from(address)),
            width,
            sign,
        }))
    }

    fn memory_address(mem: &MemOperand) -> Result<Address, LiftError> {
        let base = Self::reg(mem.base.num);
        if mem.mode == AddressingMode::PostIndex {
            return Ok(Address::Direct(base));
        }
        match &mem.offset {
            MemOffset::None | MemOffset::Imm(0) => Ok(Address::Direct(base)),
            MemOffset::Imm(offset) => Ok(Address::BaseOffset {
                base,
                offset: *offset,
                disp_size: DispSize::Auto,
            }),
            MemOffset::Reg(index) => Ok(Address::BaseIndexScale {
                base: Some(base),
                index: Self::reg(index.num),
                scale: 1,
                disp: 0,
                disp_size: DispSize::Auto,
            }),
            MemOffset::ShiftedReg(shifted)
                if shifted.shift_type == ShiftType::LSL
                    && matches!(shifted.immediate_amount(), Some(amount) if amount <= 3) =>
            {
                let amount = shifted
                    .immediate_amount()
                    .expect("guard requires immediate Thumb memory shift");
                Ok(Address::BaseIndexScale {
                    base: Some(base),
                    index: Self::reg(shifted.reg.num),
                    scale: 1 << amount,
                    disp: 0,
                    disp_size: DispSize::Auto,
                })
            }
            _ => Err(LiftError::Internal(
                "unsupported Thumb memory address escaped the hidden-state gate".to_string(),
            )),
        }
    }

    fn memory_writeback(mem: &MemOperand) -> Option<OpKind> {
        if mem.mode == AddressingMode::Offset {
            return None;
        }
        let MemOffset::Imm(offset) = &mem.offset else {
            return None;
        };
        let offset = *offset;
        let base = Self::reg(mem.base.num);
        Some(if offset < 0 {
            OpKind::Sub {
                dst: base,
                src1: base,
                src2: SrcOperand::Imm(offset.wrapping_neg()),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            }
        } else {
            OpKind::Add {
                dst: base,
                src1: base,
                src2: SrcOperand::Imm(offset),
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            }
        })
    }

    fn lift_memory(
        &self,
        insn: &DecodedInsn,
        pc: GuestAddr,
        ops: &mut Vec<SmirOp>,
    ) -> Result<(), LiftError> {
        let Some((is_load, width, sign)) = Self::memory_kind(insn.mnemonic) else {
            return Err(LiftError::Internal(
                "invalid Thumb scalar memory mnemonic".to_string(),
            ));
        };
        let [Operand::Reg(rt), Operand::Mem(mem)] = insn.operands.as_slice() else {
            return Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: "Thumb literal or malformed scalar memory operand".to_string(),
            });
        };
        let writeback = Self::memory_writeback(mem);
        if is_load && writeback.is_some() && rt.num == mem.base.num {
            return Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: "Thumb load writeback aliases its destination".to_string(),
            });
        }
        let addr = Self::memory_address(mem)?;
        Self::push(
            ops,
            pc,
            if is_load {
                OpKind::Load {
                    dst: Self::reg(rt.num),
                    addr,
                    width,
                    sign,
                }
            } else {
                OpKind::Store {
                    src: Self::reg(rt.num),
                    addr,
                    width,
                }
            },
        );
        if let Some(writeback) = writeback {
            Self::push(ops, pc, writeback);
        }
        Ok(())
    }

    fn lift_double_memory(
        &self,
        insn: &DecodedInsn,
        pc: GuestAddr,
        ops: &mut Vec<SmirOp>,
    ) -> Result<(), LiftError> {
        let [Operand::Reg(rt), Operand::Reg(rt2), Operand::Mem(mem)] = insn.operands.as_slice()
        else {
            return Err(LiftError::Internal(
                "invalid Thumb double-transfer operands".to_string(),
            ));
        };
        if rt.num >= 14 || rt.num & 1 != 0 || rt2.num != rt.num + 1 {
            return Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: "Thumb double transfer requires an adjacent even R0-R13 pair".to_string(),
            });
        }
        let is_load = insn.mnemonic == Mnemonic::LDP;
        let writeback = Self::memory_writeback(mem);
        if writeback.is_some() && (mem.base.num == rt.num || mem.base.num == rt2.num) {
            return Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: "Thumb double transfer has a constrained base/pair alias".to_string(),
            });
        }
        let addr = Self::memory_address(mem)?;
        Self::push(
            ops,
            pc,
            if is_load {
                OpKind::LoadPair {
                    dst1: Self::reg(rt.num),
                    dst2: Self::reg(rt2.num),
                    addr,
                    width: MemWidth::B4,
                }
            } else {
                OpKind::StorePair {
                    src1: Self::reg(rt.num),
                    src2: Self::reg(rt2.num),
                    addr,
                    width: MemWidth::B4,
                }
            },
        );
        if let Some(writeback) = writeback {
            Self::push(ops, pc, writeback);
        }
        Ok(())
    }

    fn multiple_kind(mnemonic: Mnemonic) -> Option<(bool, bool, bool)> {
        use Mnemonic::*;

        match mnemonic {
            LDM | LDMIA | POP => Some((true, true, false)),
            LDMIB => Some((true, true, true)),
            LDMDA => Some((true, false, false)),
            LDMDB => Some((true, false, true)),
            STM | STMIA => Some((false, true, false)),
            STMIB => Some((false, true, true)),
            STMDA => Some((false, false, false)),
            STMDB | PUSH => Some((false, false, true)),
            _ => None,
        }
    }

    fn lift_multiple_memory(
        &self,
        insn: &DecodedInsn,
        pc: GuestAddr,
        ops: &mut Vec<SmirOp>,
    ) -> Result<(), LiftError> {
        let Some((is_load, increment, before)) = Self::multiple_kind(insn.mnemonic) else {
            return Err(LiftError::Internal(
                "invalid Thumb multiple-transfer mnemonic".to_string(),
            ));
        };
        let push_pop = matches!(insn.mnemonic, Mnemonic::PUSH | Mnemonic::POP);
        let (base_num, list) = match insn.operands.as_slice() {
            [Operand::RegList(list)] if push_pop => (13, list),
            [Operand::Reg(base), Operand::RegList(list)] if !push_pop => (base.num, list),
            _ => {
                return Err(LiftError::Internal(
                    "invalid Thumb multiple-transfer operands".to_string(),
                ));
            }
        };
        let writeback =
            push_pop || insn.state == ExecutionState::Thumb || ((insn.raw >> 21) & 1) != 0;

        if base_num >= 15 || list.mask == 0 || list.contains(15) {
            return Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: "Thumb multiple transfer requires PC or empty-list semantics".to_string(),
            });
        }
        if (is_load && list.contains(base_num))
            || (!is_load && writeback && list.contains(base_num))
        {
            return Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: "Thumb multiple transfer has a constrained base/list alias".to_string(),
            });
        }

        let base = Self::reg(base_num);
        let count = i64::from(list.count());
        let low_offset = match (increment, before) {
            (true, false) => 0,
            (true, true) => 4,
            (false, false) => 4 - count * 4,
            (false, true) => -count * 4,
        };
        for (ordinal, reg_num) in list.iter().enumerate() {
            let offset = low_offset + ordinal as i64 * 4;
            let addr = if offset == 0 {
                Address::Direct(base)
            } else {
                Address::BaseOffset {
                    base,
                    offset,
                    disp_size: DispSize::Auto,
                }
            };
            Self::push(
                ops,
                pc,
                if is_load {
                    OpKind::Load {
                        dst: Self::reg(reg_num),
                        addr,
                        width: MemWidth::B4,
                        sign: SignExtend::Zero,
                    }
                } else {
                    OpKind::Store {
                        src: Self::reg(reg_num),
                        addr,
                        width: MemWidth::B4,
                    }
                },
            );
        }

        if writeback {
            let delta = count * 4;
            Self::push(
                ops,
                pc,
                if increment {
                    OpKind::Add {
                        dst: base,
                        src1: base,
                        src2: SrcOperand::Imm(delta),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    }
                } else {
                    OpKind::Sub {
                        dst: base,
                        src1: base,
                        src2: SrcOperand::Imm(delta),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    }
                },
            );
        }
        Ok(())
    }

    fn shared_scalar_mnemonic(insn: &DecodedInsn) -> bool {
        use Mnemonic::*;

        match insn.mnemonic {
            ADD | ADDS | ADC | ADCS | SUB | SUBS | SBC | SBCS | CMP | CMN | NEG | NEGS | CLZ
            | RBIT | REV | REV16 | UDIV | SDIV | NOP => true,
            SXTB | SXTH | UXTB | UXTH => {
                matches!(insn.operands.as_slice(), [Operand::Reg(_), Operand::Reg(_)])
            }
            MOV => {
                !insn.sets_flags && !matches!(insn.operands.get(1), Some(Operand::ShiftedReg(_)))
            }
            AND | ORR | EOR | BIC | MUL => !insn.sets_flags,
            LSL | LSR | ASR | ROR => {
                !insn.sets_flags && matches!(insn.operands.get(2), Some(Operand::Imm(_)))
            }
            _ => false,
        }
    }

    fn t16_partial_nz_flags() -> FlagUpdate {
        FlagUpdate::Specific(FlagSet::SF.union(FlagSet::ZF))
    }

    fn partial_nzc_flags() -> FlagUpdate {
        FlagUpdate::Specific(FlagSet::SF.union(FlagSet::ZF).union(FlagSet::CF))
    }

    /// Lift T16/T32 register-controlled shifts through the AArch32-specific
    /// low-byte-count operation. T16 has a destructive low-register encoding;
    /// T32 independently encodes destination, value, and count registers and
    /// optionally updates N/Z/C while preserving V.
    fn lift_register_shift(insn: &DecodedInsn, pc: GuestAddr, ops: &mut Vec<SmirOp>) -> bool {
        let (shift, setflags) = match insn.mnemonic {
            Mnemonic::LSL => (crate::smir::ir::types::ShiftOp::Lsl, false),
            Mnemonic::LSLS => (crate::smir::ir::types::ShiftOp::Lsl, true),
            Mnemonic::LSR => (crate::smir::ir::types::ShiftOp::Lsr, false),
            Mnemonic::LSRS => (crate::smir::ir::types::ShiftOp::Lsr, true),
            Mnemonic::ASR => (crate::smir::ir::types::ShiftOp::Asr, false),
            Mnemonic::ASRS => (crate::smir::ir::types::ShiftOp::Asr, true),
            Mnemonic::ROR => (crate::smir::ir::types::ShiftOp::Ror, false),
            Mnemonic::RORS => (crate::smir::ir::types::ShiftOp::Ror, true),
            _ => return false,
        };
        let [Operand::Reg(rd), Operand::Reg(rn), Operand::Reg(rs)] = insn.operands.as_slice()
        else {
            return false;
        };
        if insn.sets_flags != setflags {
            return false;
        }

        let valid_encoding = match (insn.state, insn.size) {
            (ExecutionState::Thumb, 2) => {
                setflags && rd.num < 8 && rn.num < 8 && rs.num < 8 && rd.num == rn.num
            }
            (ExecutionState::Thumb2, 4) => rd.num < 15 && rn.num < 15 && rs.num < 15,
            _ => false,
        };
        if !valid_encoding {
            return false;
        }

        Self::push(
            ops,
            pc,
            OpKind::ArmRegShift {
                dst: Self::reg(rd.num),
                src: Self::reg(rn.num),
                amount: SrcOperand::Reg(Self::reg(rs.num)),
                shift,
                width: OpWidth::W32,
                flags: if setflags {
                    Self::partial_nzc_flags()
                } else {
                    FlagUpdate::None
                },
            },
        );
        true
    }

    /// Lift the T16 operations whose flag contract updates only N/Z or N/Z/C.
    /// T32 S-bit forms deliberately do not enter this path. Register-controlled
    /// shifts are handled separately because their low-byte count contract
    /// differs from generic SMIR/x86 shifts.
    fn lift_t16_partial_flags(
        insn: &DecodedInsn,
        pc: GuestAddr,
        ctx: &mut LiftContext,
        ops: &mut Vec<SmirOp>,
    ) -> Result<bool, LiftError> {
        if insn.state != ExecutionState::Thumb || insn.size != 2 || !insn.sets_flags {
            return Ok(false);
        }

        let nz = Self::t16_partial_nz_flags();
        let nzc = Self::partial_nzc_flags();
        if let (Mnemonic::MOVS, [Operand::Reg(rd), Operand::Imm(imm)]) =
            (insn.mnemonic, insn.operands.as_slice())
        {
            if rd.num >= 15 {
                return Ok(false);
            }
            let dst = Self::reg(rd.num);
            Self::push(
                ops,
                pc,
                OpKind::Mov {
                    dst,
                    src: SrcOperand::Imm(imm.effective_value()),
                    width: OpWidth::W32,
                },
            );
            Self::push(
                ops,
                pc,
                OpKind::And {
                    dst,
                    src1: dst,
                    src2: SrcOperand::Imm(-1),
                    width: OpWidth::W32,
                    flags: nz,
                },
            );
            return Ok(true);
        }

        let kind = match (insn.mnemonic, insn.operands.as_slice()) {
            (Mnemonic::MOVS, [Operand::Reg(rd), Operand::Reg(rm)])
                if rd.num < 15 && rm.num < 15 =>
            {
                OpKind::And {
                    dst: Self::reg(rd.num),
                    src1: Self::reg(rm.num),
                    src2: SrcOperand::Imm(-1),
                    width: OpWidth::W32,
                    flags: nz,
                }
            }
            (
                mnemonic @ (Mnemonic::ANDS | Mnemonic::EORS | Mnemonic::ORRS | Mnemonic::BICS),
                [Operand::Reg(rd), Operand::Reg(rn), Operand::Reg(rm)],
            ) if rd.num < 15 && rn.num < 15 && rm.num < 15 => match mnemonic {
                Mnemonic::ANDS => OpKind::And {
                    dst: Self::reg(rd.num),
                    src1: Self::reg(rn.num),
                    src2: SrcOperand::Reg(Self::reg(rm.num)),
                    width: OpWidth::W32,
                    flags: nz,
                },
                Mnemonic::EORS => OpKind::Xor {
                    dst: Self::reg(rd.num),
                    src1: Self::reg(rn.num),
                    src2: SrcOperand::Reg(Self::reg(rm.num)),
                    width: OpWidth::W32,
                    flags: nz,
                },
                Mnemonic::ORRS => OpKind::Or {
                    dst: Self::reg(rd.num),
                    src1: Self::reg(rn.num),
                    src2: SrcOperand::Reg(Self::reg(rm.num)),
                    width: OpWidth::W32,
                    flags: nz,
                },
                Mnemonic::BICS => OpKind::AndNot {
                    dst: Self::reg(rd.num),
                    src1: Self::reg(rn.num),
                    src2: SrcOperand::Reg(Self::reg(rm.num)),
                    width: OpWidth::W32,
                    flags: nz,
                },
                _ => unreachable!(),
            },
            (Mnemonic::MVNS, [Operand::Reg(rd), Operand::Reg(rm)])
                if rd.num < 15 && rm.num < 15 =>
            {
                OpKind::AndNot {
                    dst: Self::reg(rd.num),
                    src1: VReg::Imm(-1),
                    src2: SrcOperand::Reg(Self::reg(rm.num)),
                    width: OpWidth::W32,
                    flags: nz,
                }
            }
            (Mnemonic::TST, [Operand::Reg(rn), Operand::Reg(rm)]) if rn.num < 15 && rm.num < 15 => {
                OpKind::And {
                    dst: ctx.alloc_vreg(),
                    src1: Self::reg(rn.num),
                    src2: SrcOperand::Reg(Self::reg(rm.num)),
                    width: OpWidth::W32,
                    flags: nz,
                }
            }
            (Mnemonic::MULS, [Operand::Reg(rd), Operand::Reg(rn), Operand::Reg(rm)])
                if rd.num < 15 && rn.num < 15 && rm.num < 15 =>
            {
                OpKind::MulU {
                    dst_lo: Self::reg(rd.num),
                    dst_hi: None,
                    src1: Self::reg(rn.num),
                    src2: SrcOperand::Reg(Self::reg(rm.num)),
                    width: OpWidth::W32,
                    flags: nz,
                }
            }
            (
                mnemonic @ (Mnemonic::LSLS | Mnemonic::LSRS | Mnemonic::ASRS),
                [Operand::Reg(rd), Operand::Reg(rm), Operand::Imm(amount)],
            ) if rd.num < 15 && rm.num < 15 => {
                let amount = SrcOperand::Imm(amount.effective_value());
                match mnemonic {
                    Mnemonic::LSLS => OpKind::Shl {
                        dst: Self::reg(rd.num),
                        src: Self::reg(rm.num),
                        amount,
                        width: OpWidth::W32,
                        flags: nzc,
                    },
                    Mnemonic::LSRS => OpKind::Shr {
                        dst: Self::reg(rd.num),
                        src: Self::reg(rm.num),
                        amount,
                        width: OpWidth::W32,
                        flags: nzc,
                    },
                    Mnemonic::ASRS => OpKind::Sar {
                        dst: Self::reg(rd.num),
                        src: Self::reg(rm.num),
                        amount,
                        width: OpWidth::W32,
                        flags: nzc,
                    },
                    _ => unreachable!(),
                }
            }
            _ => return Ok(false),
        };

        Self::push(ops, pc, kind);
        Ok(true)
    }

    fn operand_src(operand: &Operand) -> Result<SrcOperand, LiftError> {
        match operand {
            Operand::Reg(reg) if reg.num < 15 => Ok(SrcOperand::Reg(Self::reg(reg.num))),
            Operand::Imm(imm) => Ok(SrcOperand::Imm(imm.effective_value())),
            Operand::ShiftedReg(shifted)
                if shifted.reg.num < 15
                    && shifted.shift_type != ShiftType::RRX
                    && matches!(shifted.immediate_amount(), Some(amount) if amount < 32) =>
            {
                let amount = shifted
                    .immediate_amount()
                    .expect("guard requires immediate Thumb scalar shift");
                let shift = match shifted.shift_type {
                    ShiftType::LSL => crate::smir::ir::types::ShiftOp::Lsl,
                    ShiftType::LSR => crate::smir::ir::types::ShiftOp::Lsr,
                    ShiftType::ASR => crate::smir::ir::types::ShiftOp::Asr,
                    ShiftType::ROR => crate::smir::ir::types::ShiftOp::Ror,
                    ShiftType::RRX => unreachable!(),
                };
                Ok(SrcOperand::Shifted {
                    reg: Self::reg(shifted.reg.num),
                    shift,
                    amount,
                })
            }
            _ => Err(LiftError::Internal(
                "unsupported Thumb scalar source operand".to_string(),
            )),
        }
    }

    fn bitfield_fields(insn: &DecodedInsn, pc: GuestAddr) -> Result<(u8, u8, u8), LiftError> {
        let rn = ((insn.raw >> 16) & 0xf) as u8;
        let lsb = ((((insn.raw >> 12) & 0x7) << 2) | ((insn.raw >> 6) & 0x3)) as u8;
        let encoded_width = (insn.raw & 0x1f) as u8;
        if rn >= 15 && insn.mnemonic != Mnemonic::BFC {
            return Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: "Thumb bitfield source PC".to_string(),
            });
        }
        Ok((rn, lsb, encoded_width))
    }

    fn lift_decoded(
        &self,
        insn: &DecodedInsn,
        pc: GuestAddr,
        ctx: &mut LiftContext,
    ) -> Result<(Vec<SmirOp>, ControlFlow), LiftError> {
        if let Some(literal) = Self::literal_load(insn, pc)? {
            let mut ops = Vec::new();
            Self::push(&mut ops, pc, literal);
            return Ok((ops, ControlFlow::Fallthrough));
        }
        if Self::rejects_hidden_state(insn) {
            return Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: format!(
                    "Thumb {:?} requires IT, PC, register-list, or special shifter state",
                    insn.mnemonic
                ),
            });
        }

        let normalized = Self::normalize_regs(insn);
        let mut ops = Vec::new();
        if Self::lift_register_shift(&normalized, pc, &mut ops) {
            return Ok((ops, ControlFlow::Fallthrough));
        }
        if Self::lift_t16_partial_flags(&normalized, pc, ctx, &mut ops)? {
            return Ok((ops, ControlFlow::Fallthrough));
        }
        if Self::shared_scalar_mnemonic(&normalized) {
            return self.shared.lift_insn_inner(&normalized, pc, ctx);
        }

        let control = match normalized.mnemonic {
            Mnemonic::LDR
            | Mnemonic::LDRB
            | Mnemonic::LDRH
            | Mnemonic::LDRSB
            | Mnemonic::LDRSH
            | Mnemonic::STR
            | Mnemonic::STRB
            | Mnemonic::STRH => {
                self.lift_memory(&normalized, pc, &mut ops)?;
                ControlFlow::Fallthrough
            }
            // The direct executor raises the pseudocode's MemA alignment
            // fault for an address that is not word-aligned; SMIR has no
            // AArch32 alignment check (only X86CheckAlignment), so this lift
            // does not: a recorded asymmetry between the planes.
            Mnemonic::LDP | Mnemonic::STP => {
                self.lift_double_memory(&normalized, pc, &mut ops)?;
                ControlFlow::Fallthrough
            }
            Mnemonic::LDM
            | Mnemonic::LDMIA
            | Mnemonic::LDMIB
            | Mnemonic::LDMDA
            | Mnemonic::LDMDB
            | Mnemonic::STM
            | Mnemonic::STMIA
            | Mnemonic::STMIB
            | Mnemonic::STMDA
            | Mnemonic::STMDB
            | Mnemonic::PUSH
            | Mnemonic::POP => {
                self.lift_multiple_memory(&normalized, pc, &mut ops)?;
                ControlFlow::Fallthrough
            }
            Mnemonic::MVN if !normalized.sets_flags => {
                let (Some(Operand::Reg(rd)), Some(source)) =
                    (normalized.operands.first(), normalized.operands.get(1))
                else {
                    return Err(LiftError::Internal(
                        "invalid Thumb MVN operands".to_string(),
                    ));
                };
                let source = match source {
                    Operand::Reg(rm) => rm,
                    Operand::ShiftedReg(shifted)
                        if shifted.shift_type == ShiftType::LSL
                            && shifted.immediate_amount() == Some(0) =>
                    {
                        &shifted.reg
                    }
                    _ => {
                        return Err(LiftError::Unsupported {
                            addr: pc,
                            mnemonic: "shifted Thumb MVN".to_string(),
                        });
                    }
                };
                Self::push(
                    &mut ops,
                    pc,
                    OpKind::Not {
                        dst: Self::reg(rd.num),
                        src: Self::reg(source.num),
                        width: OpWidth::W32,
                    },
                );
                ControlFlow::Fallthrough
            }
            Mnemonic::MOV if !normalized.sets_flags => {
                let [Operand::Reg(rd), Operand::ShiftedReg(shifted)] =
                    normalized.operands.as_slice()
                else {
                    return Err(LiftError::Internal(
                        "invalid Thumb shifted MOV operands".to_string(),
                    ));
                };
                let dst = Self::reg(rd.num);
                let src = Self::reg(shifted.reg.num);
                let amount =
                    SrcOperand::Imm(i64::from(shifted.immediate_amount().ok_or_else(|| {
                        LiftError::Internal(
                            "Thumb MOV has register-specified shifted operand".to_string(),
                        )
                    })?));
                let flags = FlagUpdate::None;
                let kind = match shifted.shift_type {
                    ShiftType::LSL => OpKind::Shl {
                        dst,
                        src,
                        amount,
                        width: OpWidth::W32,
                        flags,
                    },
                    ShiftType::LSR => OpKind::Shr {
                        dst,
                        src,
                        amount,
                        width: OpWidth::W32,
                        flags,
                    },
                    ShiftType::ASR => OpKind::Sar {
                        dst,
                        src,
                        amount,
                        width: OpWidth::W32,
                        flags,
                    },
                    ShiftType::ROR => OpKind::Ror {
                        dst,
                        src,
                        amount,
                        width: OpWidth::W32,
                        flags,
                    },
                    ShiftType::RRX => unreachable!(),
                };
                Self::push(&mut ops, pc, kind);
                ControlFlow::Fallthrough
            }
            Mnemonic::RSB | Mnemonic::RSBS => {
                let (Some(Operand::Reg(rd)), Some(Operand::Reg(rn)), Some(operand2)) = (
                    normalized.operands.first(),
                    normalized.operands.get(1),
                    normalized.operands.get(2),
                ) else {
                    return Err(LiftError::Internal(
                        "invalid Thumb RSB operands".to_string(),
                    ));
                };
                let dst = Self::reg(rd.num);
                let rn = Self::reg(rn.num);
                match Self::operand_src(operand2)? {
                    SrcOperand::Reg(src) => Self::push(
                        &mut ops,
                        pc,
                        OpKind::Sub {
                            dst,
                            src1: src,
                            src2: SrcOperand::Reg(rn),
                            width: OpWidth::W32,
                            flags: if normalized.sets_flags {
                                FlagUpdate::All
                            } else {
                                FlagUpdate::None
                            },
                        },
                    ),
                    SrcOperand::Imm(0) => Self::push(
                        &mut ops,
                        pc,
                        OpKind::Neg {
                            dst,
                            src: rn,
                            width: OpWidth::W32,
                            flags: if normalized.sets_flags {
                                FlagUpdate::All
                            } else {
                                FlagUpdate::None
                            },
                        },
                    ),
                    SrcOperand::Imm(imm) if !normalized.sets_flags => {
                        Self::push(
                            &mut ops,
                            pc,
                            OpKind::Neg {
                                dst,
                                src: rn,
                                width: OpWidth::W32,
                                flags: FlagUpdate::None,
                            },
                        );
                        Self::push(
                            &mut ops,
                            pc,
                            OpKind::Add {
                                dst,
                                src1: dst,
                                src2: SrcOperand::Imm(imm),
                                width: OpWidth::W32,
                                flags: FlagUpdate::None,
                            },
                        );
                    }
                    _ => {
                        return Err(LiftError::Unsupported {
                            addr: pc,
                            mnemonic: "Thumb shifted or flag-setting immediate RSB".to_string(),
                        });
                    }
                }
                ControlFlow::Fallthrough
            }
            Mnemonic::MLA | Mnemonic::MLS if !normalized.sets_flags => {
                let [
                    Operand::Reg(rd),
                    Operand::Reg(rn),
                    Operand::Reg(rm),
                    Operand::Reg(ra),
                ] = normalized.operands.as_slice()
                else {
                    return Err(LiftError::Internal(
                        "invalid Thumb multiply-accumulate operands".to_string(),
                    ));
                };
                let kind = if normalized.mnemonic == Mnemonic::MLA {
                    OpKind::MulAdd {
                        dst: Self::reg(rd.num),
                        acc: Self::reg(ra.num),
                        src1: Self::reg(rn.num),
                        src2: Self::reg(rm.num),
                        width: OpWidth::W32,
                    }
                } else {
                    OpKind::MulSub {
                        dst: Self::reg(rd.num),
                        acc: Self::reg(ra.num),
                        src1: Self::reg(rn.num),
                        src2: Self::reg(rm.num),
                        width: OpWidth::W32,
                    }
                };
                Self::push(&mut ops, pc, kind);
                ControlFlow::Fallthrough
            }
            Mnemonic::UMULL | Mnemonic::SMULL if !normalized.sets_flags => {
                let [
                    Operand::Reg(lo),
                    Operand::Reg(hi),
                    Operand::Reg(rn),
                    Operand::Reg(rm),
                ] = normalized.operands.as_slice()
                else {
                    return Err(LiftError::Internal(
                        "invalid Thumb long-multiply operands".to_string(),
                    ));
                };
                let kind = if normalized.mnemonic == Mnemonic::UMULL {
                    OpKind::MulU {
                        dst_lo: Self::reg(lo.num),
                        dst_hi: Some(Self::reg(hi.num)),
                        src1: Self::reg(rn.num),
                        src2: SrcOperand::Reg(Self::reg(rm.num)),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    }
                } else {
                    OpKind::MulS {
                        dst_lo: Self::reg(lo.num),
                        dst_hi: Some(Self::reg(hi.num)),
                        src1: Self::reg(rn.num),
                        src2: SrcOperand::Reg(Self::reg(rm.num)),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    }
                };
                Self::push(&mut ops, pc, kind);
                ControlFlow::Fallthrough
            }
            Mnemonic::MOVK => {
                let (Some(Operand::Reg(rd)), Some(Operand::Imm(imm))) =
                    (normalized.operands.first(), normalized.operands.get(1))
                else {
                    return Err(LiftError::Internal(
                        "invalid Thumb MOVT operands".to_string(),
                    ));
                };
                let dst = Self::reg(rd.num);
                let imm16 = imm.effective_value() as u32 & 0xffff;
                Self::push(
                    &mut ops,
                    pc,
                    OpKind::And {
                        dst,
                        src1: dst,
                        src2: SrcOperand::Imm(0xffff),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    },
                );
                Self::push(
                    &mut ops,
                    pc,
                    OpKind::Or {
                        dst,
                        src1: dst,
                        src2: SrcOperand::Imm(i64::from(imm16 << 16)),
                        width: OpWidth::W32,
                        flags: FlagUpdate::None,
                    },
                );
                ControlFlow::Fallthrough
            }
            Mnemonic::UBFX | Mnemonic::SBFX => {
                let Some(Operand::Reg(rd)) = normalized.operands.first() else {
                    return Err(LiftError::Internal(
                        "invalid Thumb bitfield-extract operands".to_string(),
                    ));
                };
                let (rn, lsb, encoded_width) = Self::bitfield_fields(&normalized, pc)?;
                let width_bits = encoded_width + 1;
                if u16::from(lsb) + u16::from(width_bits) > 32 {
                    return Err(LiftError::Unsupported {
                        addr: pc,
                        mnemonic: "Thumb bitfield-extract bounds".to_string(),
                    });
                }
                Self::push(
                    &mut ops,
                    pc,
                    OpKind::Bfx {
                        dst: Self::reg(rd.num),
                        src: Self::reg(rn),
                        lsb,
                        width_bits,
                        sign_extend: normalized.mnemonic == Mnemonic::SBFX,
                        op_width: OpWidth::W32,
                    },
                );
                ControlFlow::Fallthrough
            }
            Mnemonic::BFI | Mnemonic::BFC => {
                let Some(Operand::Reg(rd)) = normalized.operands.first() else {
                    return Err(LiftError::Internal(
                        "invalid Thumb bitfield-insert operands".to_string(),
                    ));
                };
                let (rn, lsb, msb) = Self::bitfield_fields(&normalized, pc)?;
                if msb < lsb {
                    return Err(LiftError::Unsupported {
                        addr: pc,
                        mnemonic: "Thumb bitfield-insert bounds".to_string(),
                    });
                }
                let width_bits = msb - lsb + 1;
                let dst = Self::reg(rd.num);
                if normalized.mnemonic == Mnemonic::BFC {
                    let field_mask = if width_bits == 32 {
                        u32::MAX
                    } else {
                        ((1u32 << width_bits) - 1) << lsb
                    };
                    Self::push(
                        &mut ops,
                        pc,
                        OpKind::And {
                            dst,
                            src1: dst,
                            src2: SrcOperand::Imm(i64::from(!field_mask)),
                            width: OpWidth::W32,
                            flags: FlagUpdate::None,
                        },
                    );
                } else {
                    Self::push(
                        &mut ops,
                        pc,
                        OpKind::Bfi {
                            dst,
                            dst_in: dst,
                            src: Self::reg(rn),
                            lsb,
                            width_bits,
                            op_width: OpWidth::W32,
                        },
                    );
                }
                ControlFlow::Fallthrough
            }
            Mnemonic::B => {
                let Some(Operand::Label(offset)) = normalized.operands.first() else {
                    return Err(LiftError::Internal("invalid Thumb B operands".to_string()));
                };
                ControlFlow::Branch {
                    target: Self::add_pc_offset(pc, 4, *offset)?,
                }
            }
            Mnemonic::BCC => {
                let Some(Operand::Label(offset)) = normalized.operands.first() else {
                    return Err(LiftError::Internal(
                        "invalid Thumb BCC operands".to_string(),
                    ));
                };
                let Some(cond) = normalized.cond else {
                    return Err(LiftError::Internal(
                        "Thumb BCC is missing its condition".to_string(),
                    ));
                };
                ControlFlow::CondBranch {
                    cond: Self::branch_condition(cond, pc)?,
                    target: Self::add_pc_offset(pc, 4, *offset)?,
                    fallthrough: Self::next_pc(pc, usize::from(normalized.size))?,
                }
            }
            Mnemonic::CBZ | Mnemonic::CBNZ => {
                let [Operand::Reg(rn), Operand::Label(offset)] = normalized.operands.as_slice()
                else {
                    return Err(LiftError::Internal(
                        "invalid Thumb CBZ/CBNZ operands".to_string(),
                    ));
                };
                let target = Self::add_pc_offset(pc, 4, *offset)?;
                let fallthrough = Self::next_pc(pc, usize::from(normalized.size))?;
                if normalized.mnemonic == Mnemonic::CBNZ {
                    ControlFlow::CondBranchReg {
                        cond: Self::reg(rn.num),
                        taken: target,
                        not_taken: fallthrough,
                    }
                } else {
                    ControlFlow::CondBranchReg {
                        cond: Self::reg(rn.num),
                        taken: fallthrough,
                        not_taken: target,
                    }
                }
            }
            Mnemonic::BL => {
                let Some(Operand::Label(offset)) = normalized.operands.first() else {
                    return Err(LiftError::Internal("invalid Thumb BL operands".to_string()));
                };
                Self::push(
                    &mut ops,
                    pc,
                    OpKind::Mov {
                        dst: Self::reg(14),
                        src: SrcOperand::Imm((Self::next_pc(pc, 4)? | 1) as i64),
                        width: OpWidth::W32,
                    },
                );
                ControlFlow::Call {
                    target: CallTarget::GuestAddr(Self::add_pc_offset(pc, 4, *offset)?),
                }
            }
            Mnemonic::BLX => match normalized.operands.first() {
                Some(Operand::Label(offset)) => {
                    let aligned_pc = Self::pc32(pc)?.wrapping_add(4) & !3;
                    let target = u64::from(aligned_pc.wrapping_add(*offset as u32));
                    Self::push(
                        &mut ops,
                        pc,
                        OpKind::Mov {
                            dst: Self::reg(14),
                            src: SrcOperand::Imm((Self::next_pc(pc, 4)? | 1) as i64),
                            width: OpWidth::W32,
                        },
                    );
                    ControlFlow::Call {
                        target: CallTarget::GuestAddrInterworking {
                            addr: target,
                            thumb: false,
                        },
                    }
                }
                Some(Operand::Reg(rm)) => {
                    // The T16 register form is 2 bytes. BLX LR must snapshot the
                    // old LR before the architectural Thumb return address is
                    // written back to LR.
                    let target = if rm.num == 14 {
                        let snapshot = ctx.alloc_vreg();
                        Self::push(
                            &mut ops,
                            pc,
                            OpKind::Mov {
                                dst: snapshot,
                                src: SrcOperand::Reg(Self::reg(14)),
                                width: OpWidth::W32,
                            },
                        );
                        snapshot
                    } else {
                        Self::reg(rm.num)
                    };
                    Self::push(
                        &mut ops,
                        pc,
                        OpKind::Mov {
                            dst: Self::reg(14),
                            src: SrcOperand::Imm(
                                (Self::next_pc(pc, usize::from(normalized.size))? | 1) as i64,
                            ),
                            width: OpWidth::W32,
                        },
                    );
                    ControlFlow::Call {
                        target: CallTarget::IndirectInterworking(target),
                    }
                }
                _ => {
                    return Err(LiftError::Internal(
                        "invalid Thumb BLX operands".to_string(),
                    ));
                }
            },
            Mnemonic::BX => {
                let Some(Operand::Reg(rm)) = normalized.operands.first() else {
                    return Err(LiftError::Internal("invalid Thumb BX operands".to_string()));
                };
                ControlFlow::IndirectBranch {
                    target: Self::reg(rm.num),
                }
            }
            _ => {
                return Err(LiftError::Unsupported {
                    addr: pc,
                    mnemonic: format!("Thumb {:?}", normalized.mnemonic),
                });
            }
        };

        Ok((ops, control))
    }

    fn result(ops: Vec<SmirOp>, bytes_consumed: usize, control_flow: ControlFlow) -> LiftResult {
        let branch_targets = match &control_flow {
            ControlFlow::Branch { target } | ControlFlow::DirectBranch(target) => vec![*target],
            ControlFlow::CondBranch {
                target,
                fallthrough,
                ..
            } => vec![*target, *fallthrough],
            ControlFlow::CondBranchReg {
                taken, not_taken, ..
            } => vec![*taken, *not_taken],
            ControlFlow::Call {
                target: CallTarget::GuestAddr(target),
            } => vec![*target],
            ControlFlow::Call {
                target: CallTarget::GuestAddrInterworking { addr, .. },
            } => vec![*addr],
            _ => Vec::new(),
        };
        LiftResult {
            ops,
            bytes_consumed,
            control_flow,
            branch_targets,
        }
    }

    fn decode(bytes: &[u8], addr: GuestAddr) -> Result<DecodedInsn, LiftError> {
        if bytes.len() < 2 {
            return Err(LiftError::Incomplete {
                addr,
                have: bytes.len(),
                need: 2,
            });
        }
        let hw1 = u16::from_le_bytes(bytes[..2].try_into().unwrap());
        let need = if ThumbDecoder::is_32bit_instruction(hw1) {
            4
        } else {
            2
        };
        if bytes.len() < need {
            return Err(LiftError::Incomplete {
                addr,
                have: bytes.len(),
                need,
            });
        }
        Decoder::new(ExecutionState::Thumb)
            .decode(&bytes[..need])
            .map_err(|_| LiftError::InvalidEncoding {
                addr,
                bytes: bytes[..need].to_vec(),
            })
    }
}

impl Default for ThumbLifter {
    fn default() -> Self {
        Self::new()
    }
}

impl SmirLifter for ThumbLifter {
    fn source_arch(&self) -> SourceArch {
        SourceArch::Thumb
    }

    fn lift_insn(
        &mut self,
        addr: GuestAddr,
        bytes: &[u8],
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        Self::pc32(addr)?;
        let insn = Self::decode(bytes, addr)?;
        ctx.guest_pc = addr;
        let bytes_consumed = insn.size as usize;
        let (ops, control) = self.lift_decoded(&insn, addr, ctx)?;
        Ok(Self::result(ops, bytes_consumed, control))
    }

    fn lift_block(
        &mut self,
        addr: GuestAddr,
        mem: &dyn MemoryReader,
        ctx: &mut LiftContext,
    ) -> Result<SmirBlock, LiftError> {
        let block_id = ctx.get_or_create_block(addr);
        let mut ops = Vec::new();
        let mut pc = addr;

        loop {
            let prefix = mem
                .read(pc, 2)
                .map_err(|error| LiftError::MemoryError { addr: pc, error })?;
            let hw1 = u16::from_le_bytes(prefix[..2].try_into().unwrap());
            let bytes = if ThumbDecoder::is_32bit_instruction(hw1) {
                mem.read(pc, 4)
                    .map_err(|error| LiftError::MemoryError { addr: pc, error })?
            } else {
                prefix
            };
            let result = self.lift_insn(pc, &bytes, ctx)?;
            let insn_pc = pc;
            pc = Self::next_pc(pc, result.bytes_consumed)?;
            for mut op in result.ops {
                op.id = OpId(ops.len() as u16);
                ops.push(op);
            }
            if !result.control_flow.ends_block() {
                continue;
            }

            let terminator = match result.control_flow {
                ControlFlow::Branch { target } | ControlFlow::DirectBranch(target) => {
                    Terminator::Branch {
                        target: ctx.get_or_create_block(target),
                    }
                }
                ControlFlow::Call { target } => Terminator::Call {
                    target,
                    args: Vec::new(),
                    continuation: ctx.get_or_create_block(pc),
                },
                ControlFlow::CondBranch {
                    cond,
                    target,
                    fallthrough,
                } => {
                    let cond_vreg = ctx.alloc_vreg();
                    ops.push(SmirOp::new(
                        OpId(ops.len() as u16),
                        insn_pc,
                        OpKind::TestCondition {
                            dst: cond_vreg,
                            cond,
                        },
                    ));
                    Terminator::CondBranch {
                        cond: cond_vreg,
                        true_target: ctx.get_or_create_block(target),
                        false_target: ctx.get_or_create_block(fallthrough),
                    }
                }
                ControlFlow::CondBranchReg {
                    cond,
                    taken,
                    not_taken,
                } => Terminator::CondBranch {
                    cond,
                    true_target: ctx.get_or_create_block(taken),
                    false_target: ctx.get_or_create_block(not_taken),
                },
                ControlFlow::IndirectBranch { target } => Terminator::IndirectBranch {
                    target,
                    possible_targets: Vec::new(),
                },
                ControlFlow::Return => Terminator::Return { values: Vec::new() },
                ControlFlow::Trap { kind } => Terminator::Trap { kind },
                ControlFlow::Syscall => Terminator::Trap {
                    kind: TrapKind::SystemCall,
                },
                ControlFlow::IndirectBranchMem { .. } => {
                    return Err(LiftError::Unsupported {
                        addr: insn_pc,
                        mnemonic: "Thumb block terminator".to_string(),
                    });
                }
                ControlFlow::Fallthrough | ControlFlow::NextInsn => unreachable!(),
            };
            return Ok(SmirBlock {
                id: block_id,
                guest_pc: addr,
                phis: Vec::new(),
                ops,
                terminator,
                exec_count: 0,
            });
        }
    }

    fn lift_function(
        &mut self,
        entry: GuestAddr,
        mem: &dyn MemoryReader,
        ctx: &mut LiftContext,
    ) -> Result<SmirFunction, LiftError> {
        let id = FunctionId(ctx.known_functions.len() as u32);
        ctx.known_functions.insert(entry, id);
        let mut worklist = vec![entry];
        let mut visited = HashSet::new();
        let mut blocks = Vec::new();

        while let Some(addr) = worklist.pop() {
            if !visited.insert(addr) {
                continue;
            }
            let block = self.lift_block(addr, mem, ctx)?;
            for successor in block.successors() {
                if let Some((&successor_addr, _)) =
                    ctx.block_cache.iter().find(|(_, id)| **id == successor)
                {
                    if !visited.contains(&successor_addr) {
                        worklist.push(successor_addr);
                    }
                }
            }
            blocks.push(block);
        }

        let min = blocks
            .iter()
            .map(|block| block.guest_pc)
            .min()
            .unwrap_or(entry);
        let max = blocks
            .iter()
            .map(|block| block.guest_pc.wrapping_add(4))
            .max()
            .unwrap_or(entry.wrapping_add(2));
        Ok(SmirFunction {
            id,
            entry: ctx.get_or_create_block(entry),
            blocks,
            locals: Vec::new(),
            guest_range: (min, max),
            calling_convention: CallingConv::GuestPreserveAll,
            attrs: FunctionAttrs::default(),
            x86_instruction_bytes: std::collections::HashMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smir::ir::types::ShiftOp;

    fn lift(bytes: &[u8]) -> LiftResult {
        let mut lifter = ThumbLifter::new();
        let mut ctx = LiftContext::new(SourceArch::Thumb);
        lifter.lift_insn(0x1000, bytes, &mut ctx).unwrap()
    }

    #[test]
    fn lifts_mixed_t16_t32_scalar_matrix_with_exact_lengths() {
        let cases: &[(&[u8], usize, &str)] = &[
            (&[0x88, 0x18], 2, "adds-t16"),
            (&[0x63, 0x1f], 2, "subs-t16"),
            (&[0x75, 0x41], 2, "adcs-t16"),
            (&[0x87, 0x41], 2, "sbcs-t16"),
            (&[0x80, 0x29], 2, "cmp-t16"),
            (&[0xda, 0x42], 2, "cmn-t16"),
            (&[0x6c, 0x42], 2, "neg-t16"),
            (&[0xc8, 0x44], 2, "add-high-t16"),
            (&[0xda, 0x46], 2, "mov-high-t16"),
            (&[0x08, 0xba], 2, "rev-t16"),
            (&[0x01, 0xeb, 0xc2, 0x00], 4, "add-shift-t32"),
            (&[0x0c, 0xea, 0x70, 0x1b], 4, "and-ror-t32"),
            (&[0x09, 0xfb, 0x0a, 0xf8], 4, "mul-t32"),
            (&[0x04, 0xfb, 0x05, 0x63], 4, "mla-t32"),
            (&[0xa2, 0xfb, 0x03, 0x01], 4, "umull-t32"),
            (&[0xb9, 0xfb, 0xfa, 0xf8], 4, "udiv-t32"),
            (&[0xb2, 0xfa, 0x82, 0xf1], 4, "clz-t32"),
            (&[0x6a, 0xf3, 0x0f, 0x29], 4, "bfi-t32"),
            (&[0xcc, 0xf3, 0x06, 0x3b], 4, "ubfx-t32"),
            (&[0x4f, 0xfa, 0x83, 0xf2], 4, "sxtb-t32"),
            (&[0xcc, 0xf6, 0xfe, 0x27], 4, "movt-t32"),
        ];
        for (bytes, expected_len, label) in cases {
            let mut lifter = ThumbLifter::new();
            let mut ctx = LiftContext::new(SourceArch::Thumb);
            let result = lifter
                .lift_insn(0x1000, bytes, &mut ctx)
                .unwrap_or_else(|error| panic!("{label}: {error:?}"));
            assert_eq!(result.bytes_consumed, *expected_len, "{label}");
            assert!(!result.ops.is_empty(), "{label}");
            assert!(matches!(result.control_flow, ControlFlow::Fallthrough));
        }
    }

    #[test]
    fn lifts_t16_scalar_memory_width_sign_and_address_matrix() {
        let cases: &[(&[u8], MemWidth, SignExtend, bool)] = &[
            (&[0x88, 0x50], MemWidth::B4, SignExtend::Zero, false), // str r0,[r1,r2]
            (&[0x88, 0x52], MemWidth::B2, SignExtend::Zero, false), // strh r0,[r1,r2]
            (&[0x88, 0x54], MemWidth::B1, SignExtend::Zero, false), // strb r0,[r1,r2]
            (&[0x88, 0x56], MemWidth::B1, SignExtend::Sign, true),  // ldrsb r0,[r1,r2]
            (&[0x88, 0x58], MemWidth::B4, SignExtend::Zero, true),  // ldr r0,[r1,r2]
            (&[0x88, 0x5a], MemWidth::B2, SignExtend::Zero, true),  // ldrh r0,[r1,r2]
            (&[0x88, 0x5c], MemWidth::B1, SignExtend::Zero, true),  // ldrb r0,[r1,r2]
            (&[0x88, 0x5e], MemWidth::B2, SignExtend::Sign, true),  // ldrsh r0,[r1,r2]
            (&[0x48, 0x68], MemWidth::B4, SignExtend::Zero, true),  // ldr r0,[r1,#4]
            (&[0x88, 0x78], MemWidth::B1, SignExtend::Zero, true),  // ldrb r0,[r1,#2]
            (&[0x48, 0x88], MemWidth::B2, SignExtend::Zero, true),  // ldrh r0,[r1,#2]
            (&[0x01, 0x98], MemWidth::B4, SignExtend::Zero, true),  // ldr r0,[sp,#4]
        ];

        for (bytes, width, sign, is_load) in cases {
            let result = lift(bytes);
            assert_eq!(result.bytes_consumed, 2);
            assert_eq!(result.ops.len(), 1);
            match &result.ops[0].kind {
                OpKind::Load {
                    width: actual_width,
                    sign: actual_sign,
                    ..
                } if *is_load => {
                    assert_eq!(actual_width, width, "{bytes:02x?}");
                    assert_eq!(actual_sign, sign, "{bytes:02x?}");
                }
                OpKind::Store {
                    width: actual_width,
                    ..
                } if !*is_load => assert_eq!(actual_width, width, "{bytes:02x?}"),
                other => panic!("unexpected T16 memory lift {bytes:02x?}: {other:?}"),
            }
        }
    }

    #[test]
    fn lifts_t32_memory_writeback_after_access_and_scaled_offsets() {
        let cases: &[(&[u8], MemWidth, SignExtend, bool, usize)] = &[
            (
                &[0x51, 0xf8, 0x04, 0x0f],
                MemWidth::B4,
                SignExtend::Zero,
                true,
                2,
            ), // ldr r0,[r1,#4]!
            (
                &[0x43, 0xf8, 0x08, 0x29],
                MemWidth::B4,
                SignExtend::Zero,
                false,
                2,
            ), // str r2,[r3],#-8
            (
                &[0x95, 0xf9, 0x07, 0x40],
                MemWidth::B1,
                SignExtend::Sign,
                true,
                1,
            ), // ldrsb.w r4,[r5,#7]
            (
                &[0x37, 0xf9, 0x00, 0x60],
                MemWidth::B2,
                SignExtend::Sign,
                true,
                1,
            ), // ldrsh.w r6,[r7,r0]
            (
                &[0x8d, 0xf8, 0x0c, 0x80],
                MemWidth::B1,
                SignExtend::Zero,
                false,
                1,
            ), // strb.w r8,[sp,#12]
            (
                &[0x2a, 0xf8, 0x04, 0x9d],
                MemWidth::B2,
                SignExtend::Zero,
                false,
                2,
            ), // strh r9,[r10,#-4]!
        ];

        for (bytes, width, sign, is_load, op_count) in cases {
            let result = lift(bytes);
            assert_eq!(result.bytes_consumed, 4, "{bytes:02x?}");
            assert_eq!(result.ops.len(), *op_count, "{bytes:02x?}");
            match &result.ops[0].kind {
                OpKind::Load {
                    width: actual_width,
                    sign: actual_sign,
                    ..
                } if *is_load => {
                    assert_eq!(actual_width, width, "{bytes:02x?}");
                    assert_eq!(actual_sign, sign, "{bytes:02x?}");
                }
                OpKind::Store {
                    width: actual_width,
                    ..
                } if !*is_load => assert_eq!(actual_width, width, "{bytes:02x?}"),
                other => panic!("unexpected T32 memory lift {bytes:02x?}: {other:?}"),
            }
            if result.ops.len() == 2 {
                assert!(
                    matches!(
                        result.ops[1].kind,
                        OpKind::Add {
                            width: OpWidth::W32,
                            flags: FlagUpdate::None,
                            ..
                        } | OpKind::Sub {
                            width: OpWidth::W32,
                            flags: FlagUpdate::None,
                            ..
                        }
                    ),
                    "writeback follows access for {bytes:02x?}"
                );
            }
        }
    }

    #[test]
    fn lifts_t16_t32_multiple_transfers_with_ordered_writeback() {
        fn offset(op: &SmirOp) -> i64 {
            let addr = match &op.kind {
                OpKind::Load { addr, .. } | OpKind::Store { addr, .. } => addr,
                other => panic!("expected transfer, got {other:?}"),
            };
            match addr {
                Address::Direct(_) => 0,
                Address::BaseOffset { offset, .. } => *offset,
                other => panic!("unexpected multiple-transfer address {other:?}"),
            }
        }

        let push = lift(&[0x31, 0xb5]); // push {r0,r4,r5,lr}
        assert_eq!(push.bytes_consumed, 2);
        assert_eq!(
            push.ops[..4].iter().map(offset).collect::<Vec<_>>(),
            vec![-16, -12, -8, -4]
        );
        assert!(matches!(
            &push.ops[4].kind,
            OpKind::Sub {
                dst,
                src1,
                src2: SrcOperand::Imm(16),
                ..
            } if dst == src1 && *dst == ThumbLifter::reg(13)
        ));

        let ldm = lift(&[0x07, 0xcf]); // ldmia r7!,{r0-r2}
        assert_eq!(ldm.bytes_consumed, 2);
        assert_eq!(
            ldm.ops[..3].iter().map(offset).collect::<Vec<_>>(),
            vec![0, 4, 8]
        );
        assert!(matches!(
            &ldm.ops[3].kind,
            OpKind::Add {
                dst,
                src1,
                src2: SrcOperand::Imm(12),
                ..
            } if dst == src1 && *dst == ThumbLifter::reg(7)
        ));

        let push_w = lift(&[0x2d, 0xe9, 0x00, 0x4f]); // push.w {r8-r11,lr}
        assert_eq!(push_w.bytes_consumed, 4);
        assert_eq!(push_w.ops.len(), 6);
        assert_eq!(
            push_w.ops[..5].iter().map(offset).collect::<Vec<_>>(),
            vec![-20, -16, -12, -8, -4]
        );

        let stmdb_w = lift(&[0x2a, 0xe9, 0x05, 0x01]); // stmdb r10!,{r0,r2,r8}
        assert_eq!(stmdb_w.bytes_consumed, 4);
        assert_eq!(
            stmdb_w.ops[..3].iter().map(offset).collect::<Vec<_>>(),
            vec![-12, -8, -4]
        );
    }

    #[test]
    fn thumb_multiple_transfers_reject_pc_empty_and_base_aliases() {
        let cases: &[&[u8]] = &[
            &[0x01, 0xbd],             // pop {r0,pc}: interworking control flow
            &[0x00, 0xb4],             // push {}: constrained empty list
            &[0x02, 0xc9],             // ldmia r1!,{r1}: load/base alias
            &[0x02, 0xc1],             // stmia r1!,{r1}: store/writeback alias
            &[0xbd, 0xe8, 0x00, 0x80], // pop.w {pc}
        ];
        for bytes in cases {
            let mut lifter = ThumbLifter::new();
            let mut ctx = LiftContext::new(SourceArch::Thumb);
            assert!(
                matches!(
                    lifter.lift_insn(0x1000, bytes, &mut ctx),
                    Err(LiftError::Unsupported { .. })
                ),
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn lifts_t32_double_transfers_with_pair_atomicity_and_writeback() {
        let load = lift(&[0xd2, 0xe9, 0x02, 0x01]); // ldrd r0,r1,[r2,#8]
        assert!(matches!(
            load.ops.as_slice(),
            [SmirOp {
                kind: OpKind::LoadPair {
                    dst1,
                    dst2,
                    addr: Address::BaseOffset {
                        base,
                        offset: 8,
                        ..
                    },
                    width: MemWidth::B4,
                },
                ..
            }] if *dst1 == ThumbLifter::reg(0)
                && *dst2 == ThumbLifter::reg(1)
                && *base == ThumbLifter::reg(2)
        ));

        let store = lift(&[0xe4, 0xe9, 0x02, 0x23]); // strd r2,r3,[r4,#8]!
        assert!(matches!(
            store.ops.as_slice(),
            [
                SmirOp {
                    kind: OpKind::StorePair {
                        src1,
                        src2,
                        addr: Address::BaseOffset { offset: 8, .. },
                        width: MemWidth::B4,
                    },
                    ..
                },
                SmirOp {
                    kind: OpKind::Add {
                        dst,
                        src1: base,
                        src2: SrcOperand::Imm(8),
                        ..
                    },
                    ..
                }
            ] if *src1 == ThumbLifter::reg(2)
                && *src2 == ThumbLifter::reg(3)
                && dst == base
                && *dst == ThumbLifter::reg(4)
        ));
    }

    #[test]
    fn thumb_double_transfers_reject_nonadjacent_pc_and_writeback_alias_pairs() {
        let cases: &[&[u8]] = &[
            &[0xd2, 0xe9, 0x02, 0x12], // ldrd r1,r2,[r2,#8]: odd first register
            &[0xd2, 0xe9, 0x02, 0x02], // ldrd r0,r2,[r2,#8]: nonadjacent pair
            &[0xd2, 0xe9, 0x02, 0xef], // ldrd r14,pc,[r2,#8]
            &[0xf0, 0xe9, 0x02, 0x01], // ldrd r0,r1,[r0,#8]!: base alias
        ];
        for bytes in cases {
            let mut lifter = ThumbLifter::new();
            let mut ctx = LiftContext::new(SourceArch::Thumb);
            assert!(
                matches!(
                    lifter.lift_insn(0x1000, bytes, &mut ctx),
                    Err(LiftError::Unsupported { .. })
                ),
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn uses_thumb_pc_plus_four_and_sets_thumb_link_bit() {
        let branch = lift(&[0x04, 0xe0]); // B +8; target = 0x100c.
        assert!(matches!(
            branch.control_flow,
            ControlFlow::Branch { target: 0x100c }
        ));

        let t16_cond = lift(&[0x01, 0xd0]); // BEQ +2.
        assert!(matches!(
            t16_cond.control_flow,
            ControlFlow::CondBranch {
                cond: Condition::Eq,
                target: 0x1006,
                fallthrough: 0x1002,
            }
        ));
        assert_eq!(t16_cond.branch_targets, vec![0x1006, 0x1002]);

        let t32_cond = lift(&[0x40, 0xf0, 0x02, 0x80]); // BNE.W +4.
        assert_eq!(t32_cond.bytes_consumed, 4);
        assert!(matches!(
            t32_cond.control_flow,
            ControlFlow::CondBranch {
                cond: Condition::Ne,
                target: 0x1008,
                fallthrough: 0x1004,
            }
        ));
        assert_eq!(t32_cond.branch_targets, vec![0x1008, 0x1004]);

        let call = lift(&[0x00, 0xf0, 0x00, 0xf8]); // BL +0.
        assert!(matches!(
            call.control_flow,
            ControlFlow::Call {
                target: CallTarget::GuestAddr(0x1004)
            }
        ));
        assert!(matches!(
            call.ops.as_slice(),
            [SmirOp {
                kind: OpKind::Mov {
                    dst: VReg::Arch(ArchReg::Arm(ArmReg::X(14))),
                    src: SrcOperand::Imm(0x1005),
                    width: OpWidth::W32,
                },
                ..
            }]
        ));
    }

    #[test]
    fn lifts_t16_cbz_cbnz_for_every_low_register_and_max_forward_offset() {
        for rn in 0_u16..8 {
            for (base, zero) in [(0xb100_u16, true), (0xb900_u16, false)] {
                let raw = base | (1 << 3) | rn; // forward offset = 2.
                let result = lift(&raw.to_le_bytes());
                let reg = ThumbLifter::reg(rn as u8);
                assert_eq!(result.bytes_consumed, 2);
                assert!(result.ops.is_empty());
                assert!(matches!(
                    result.control_flow,
                    ControlFlow::CondBranchReg {
                        cond,
                        taken,
                        not_taken,
                    } if cond == reg
                        && if zero {
                            taken == 0x1002 && not_taken == 0x1006
                        } else {
                            taken == 0x1006 && not_taken == 0x1002
                        }
                ));
            }
        }

        for (raw, zero) in [(0xb3f8_u16, true), (0xbbf8_u16, false)] {
            let result = lift(&raw.to_le_bytes()); // r0, forward offset = 126.
            assert!(matches!(
                result.control_flow,
                ControlFlow::CondBranchReg {
                    taken,
                    not_taken,
                    ..
                } if if zero {
                    taken == 0x1002 && not_taken == 0x1082
                } else {
                    taken == 0x1082 && not_taken == 0x1002
                }
            ));
        }
    }

    #[test]
    fn lifts_t16_bx_for_every_non_pc_register_and_block_terminator() {
        for rm in 0_u16..15 {
            let result = lift(&(0x4700 | (rm << 3)).to_le_bytes());
            assert!(result.ops.is_empty());
            assert!(result.branch_targets.is_empty());
            assert!(matches!(
                result.control_flow,
                ControlFlow::IndirectBranch { target }
                    if target == ThumbLifter::reg(rm as u8)
            ));
        }
        let mut lifter = ThumbLifter::new();
        let mut reject_ctx = LiftContext::new(SourceArch::Thumb);
        assert!(matches!(
            lifter.lift_insn(0x1000, &[0x78, 0x47], &mut reject_ctx),
            Err(LiftError::Unsupported { .. })
        ));

        struct Memory([u8; 2]);
        impl MemoryReader for Memory {
            fn read(
                &self,
                addr: GuestAddr,
                size: usize,
            ) -> Result<Vec<u8>, crate::smir::ir::memory::MemoryError> {
                if addr != 0x1000 || size != 2 {
                    return Err(crate::smir::ir::memory::MemoryError::OutOfBounds { addr });
                }
                Ok(self.0.to_vec())
            }
        }

        let mut lifter = ThumbLifter::new();
        let mut ctx = LiftContext::new(SourceArch::Thumb);
        let block = lifter
            .lift_block(0x1000, &Memory([0x70, 0x47]), &mut ctx)
            .unwrap();
        assert!(block.ops.is_empty());
        assert!(matches!(
            block.terminator,
            Terminator::IndirectBranch {
                target: VReg::Arch(ArchReg::Arm(ArmReg::X(14))),
                ref possible_targets,
            } if possible_targets.is_empty()
        ));
    }

    #[test]
    fn lifts_thumb_blx_immediate_and_every_register_with_old_lr_snapshot() {
        let direct = lift(&[0x00, 0xf0, 0x00, 0xe8]); // BLX +0: Thumb -> ARM.
        assert_eq!(direct.bytes_consumed, 4);
        assert_eq!(direct.branch_targets, vec![0x1004]);
        assert!(matches!(
            direct.control_flow,
            ControlFlow::Call {
                target: CallTarget::GuestAddrInterworking {
                    addr: 0x1004,
                    thumb: false,
                }
            }
        ));
        assert!(matches!(
            direct.ops.as_slice(),
            [SmirOp {
                kind: OpKind::Mov {
                    dst: VReg::Arch(ArchReg::Arm(ArmReg::X(14))),
                    src: SrcOperand::Imm(0x1005),
                    width: OpWidth::W32,
                },
                ..
            }]
        ));

        let mut unaligned_lifter = ThumbLifter::new();
        let mut unaligned_ctx = LiftContext::new(SourceArch::Thumb);
        let unaligned = unaligned_lifter
            .lift_insn(0x1002, &[0x00, 0xf0, 0x00, 0xe8], &mut unaligned_ctx)
            .unwrap();
        assert!(matches!(
            unaligned.control_flow,
            ControlFlow::Call {
                target: CallTarget::GuestAddrInterworking {
                    addr: 0x1004,
                    thumb: false,
                }
            }
        ));

        for rm in 0_u16..15 {
            let result = lift(&(0x4780 | (rm << 3)).to_le_bytes());
            assert_eq!(result.bytes_consumed, 2);
            assert!(result.branch_targets.is_empty());
            match (rm, result.ops.as_slice(), result.control_flow) {
                (
                    14,
                    [
                        SmirOp {
                            kind:
                                OpKind::Mov {
                                    dst: snapshot,
                                    src: SrcOperand::Reg(source),
                                    width: OpWidth::W32,
                                },
                            ..
                        },
                        SmirOp {
                            kind:
                                OpKind::Mov {
                                    dst: link,
                                    src: SrcOperand::Imm(0x1003),
                                    width: OpWidth::W32,
                                },
                            ..
                        },
                    ],
                    ControlFlow::Call {
                        target: CallTarget::IndirectInterworking(target),
                    },
                ) => {
                    assert!(matches!(snapshot, VReg::Virtual(_)));
                    assert_eq!(*source, ThumbLifter::reg(14));
                    assert_eq!(*link, ThumbLifter::reg(14));
                    assert_eq!(target, *snapshot);
                }
                (
                    _,
                    [
                        SmirOp {
                            kind:
                                OpKind::Mov {
                                    dst,
                                    src: SrcOperand::Imm(0x1003),
                                    width: OpWidth::W32,
                                },
                            ..
                        },
                    ],
                    ControlFlow::Call {
                        target: CallTarget::IndirectInterworking(target),
                    },
                ) => {
                    assert_eq!(*dst, ThumbLifter::reg(14));
                    assert_eq!(target, ThumbLifter::reg(rm as u8));
                }
                other => panic!("unexpected BLX r{rm} lift: {other:?}"),
            }
        }

        let mut lifter = ThumbLifter::new();
        let mut ctx = LiftContext::new(SourceArch::Thumb);
        assert!(matches!(
            lifter.lift_insn(0x1000, &[0xf8, 0x47], &mut ctx),
            Err(LiftError::Unsupported { .. })
        ));
    }

    #[test]
    fn thumb_control_flow_pc_arithmetic_wraps_modulo_2_pow_32() {
        let mut lifter = ThumbLifter::new();
        let mut ctx = LiftContext::new(SourceArch::Thumb);

        let branch = lifter
            .lift_insn(0xffff_fffe, &[0x00, 0xe0], &mut ctx)
            .unwrap(); // B +0: PC + 4 wraps to 2.
        assert!(matches!(
            branch.control_flow,
            ControlFlow::Branch { target: 2 }
        ));

        let cond = lifter
            .lift_insn(0xffff_fffe, &[0x00, 0xd0], &mut ctx)
            .unwrap(); // BEQ +0; fallthrough wraps to 0.
        assert!(matches!(
            cond.control_flow,
            ControlFlow::CondBranch {
                target: 2,
                fallthrough: 0,
                ..
            }
        ));

        let cbz = lifter
            .lift_insn(0xffff_fffe, &[0x00, 0xb1], &mut ctx)
            .unwrap();
        assert!(matches!(
            cbz.control_flow,
            ControlFlow::CondBranchReg {
                taken: 0,
                not_taken: 2,
                ..
            }
        ));

        let call = lifter
            .lift_insn(0xffff_fffc, &[0x00, 0xf0, 0x00, 0xf8], &mut ctx)
            .unwrap(); // BL +0; target 0, Thumb link 1.
        assert!(matches!(
            call.control_flow,
            ControlFlow::Call {
                target: CallTarget::GuestAddr(0)
            }
        ));
        assert!(matches!(
            call.ops.as_slice(),
            [SmirOp {
                kind: OpKind::Mov {
                    src: SrcOperand::Imm(1),
                    ..
                },
                ..
            }]
        ));

        let exchange = lifter
            .lift_insn(0xffff_fffe, &[0x00, 0xf0, 0x00, 0xe8], &mut ctx)
            .unwrap(); // BLX +0; aligned PC base wraps to 0, Thumb link wraps to 3.
        assert!(matches!(
            exchange.control_flow,
            ControlFlow::Call {
                target: CallTarget::GuestAddrInterworking {
                    addr: 0,
                    thumb: false,
                }
            }
        ));
        assert!(matches!(
            exchange.ops.as_slice(),
            [SmirOp {
                kind: OpKind::Mov {
                    src: SrcOperand::Imm(3),
                    ..
                },
                ..
            }]
        ));

        assert!(matches!(
            lifter.lift_insn(u64::from(u32::MAX) + 1, &[0x00, 0xe0], &mut ctx),
            Err(LiftError::Unsupported { .. })
        ));
    }

    #[test]
    fn lifts_every_t16_branch_condition_with_exact_fallthrough() {
        let conditions = [
            Condition::Eq,
            Condition::Ne,
            Condition::Uge,
            Condition::Ult,
            Condition::Negative,
            Condition::Positive,
            Condition::Overflow,
            Condition::NoOverflow,
            Condition::Ugt,
            Condition::Ule,
            Condition::Sge,
            Condition::Slt,
            Condition::Sgt,
            Condition::Sle,
        ];

        for (bits, expected) in conditions.into_iter().enumerate() {
            let raw = 0xd001u16 | ((bits as u16) << 8);
            let result = lift(&raw.to_le_bytes());
            assert!(matches!(
                result.control_flow,
                ControlFlow::CondBranch {
                    cond,
                    target: 0x1006,
                    fallthrough: 0x1002,
                } if cond == expected
            ));
            assert_eq!(result.branch_targets, vec![0x1006, 0x1002]);
        }
    }

    #[test]
    fn lifts_t16_selective_flag_move_logic_multiply_and_immediate_shift_matrix() {
        let nz = ThumbLifter::t16_partial_nz_flags();
        let nzc = ThumbLifter::partial_nzc_flags();

        assert!(matches!(
            lift(&[0x00, 0x20]).ops.as_slice(),
            [
                SmirOp {
                    kind: OpKind::Mov {
                        dst,
                        src: SrcOperand::Imm(0),
                        width: OpWidth::W32,
                    },
                    ..
                },
                SmirOp {
                    kind: OpKind::And {
                        dst: flags_dst,
                        src1,
                        src2: SrcOperand::Imm(-1),
                        width: OpWidth::W32,
                        flags,
                    },
                    ..
                }
            ] if *dst == ThumbLifter::reg(0)
                && *flags_dst == *dst
                && *src1 == *dst
                && *flags == nz
        ));
        assert!(matches!(
            lift(&[0x08, 0x00]).ops.as_slice(),
            [SmirOp {
                kind: OpKind::And {
                    dst,
                    src1,
                    src2: SrcOperand::Imm(-1),
                    width: OpWidth::W32,
                    flags,
                },
                ..
            }] if *dst == ThumbLifter::reg(0)
                && *src1 == ThumbLifter::reg(1)
                && *flags == nz
        ));

        for (bytes, expected) in [
            ([0x08, 0x40], "and"),
            ([0x48, 0x40], "xor"),
            ([0x08, 0x43], "or"),
            ([0x88, 0x43], "and-not"),
        ] {
            let result = lift(&bytes);
            let matched = match (&result.ops[0].kind, expected) {
                (OpKind::And { flags, .. }, "and")
                | (OpKind::Xor { flags, .. }, "xor")
                | (OpKind::Or { flags, .. }, "or")
                | (OpKind::AndNot { flags, .. }, "and-not") => *flags == nz,
                _ => false,
            };
            assert!(matched, "{bytes:02x?}: {result:?}");
        }

        assert!(matches!(
            lift(&[0xc8, 0x43]).ops.as_slice(),
            [SmirOp {
                kind: OpKind::AndNot {
                    dst,
                    src1: VReg::Imm(-1),
                    flags,
                    ..
                },
                ..
            }] if *dst == ThumbLifter::reg(0) && *flags == nz
        ));
        assert!(matches!(
            lift(&[0x08, 0x42]).ops.as_slice(),
            [SmirOp {
                kind: OpKind::And {
                    dst: VReg::Virtual(_),
                    flags,
                    ..
                },
                ..
            }] if *flags == nz
        ));
        assert!(matches!(
            lift(&[0x48, 0x43]).ops.as_slice(),
            [SmirOp {
                kind: OpKind::MulU {
                    dst_lo,
                    dst_hi: None,
                    width: OpWidth::W32,
                    flags,
                    ..
                },
                ..
            }] if *dst_lo == ThumbLifter::reg(0) && *flags == nz
        ));

        for (bytes, expected_amount, expected) in [
            ([0x48, 0x00], 1, "lsl"),
            ([0xc8, 0x0f], 31, "lsr"),
            ([0x08, 0x08], 32, "lsr"),
            ([0xc8, 0x17], 31, "asr"),
            ([0x08, 0x10], 32, "asr"),
        ] {
            let result = lift(&bytes);
            let matched = match (&result.ops[0].kind, expected) {
                (
                    OpKind::Shl {
                        amount: SrcOperand::Imm(amount),
                        flags,
                        ..
                    },
                    "lsl",
                )
                | (
                    OpKind::Shr {
                        amount: SrcOperand::Imm(amount),
                        flags,
                        ..
                    },
                    "lsr",
                )
                | (
                    OpKind::Sar {
                        amount: SrcOperand::Imm(amount),
                        flags,
                        ..
                    },
                    "asr",
                ) => *amount == expected_amount && *flags == nzc,
                _ => false,
            };
            assert!(matched, "{bytes:02x?}: {result:?}");
        }
    }

    #[test]
    fn lifts_all_t16_register_shift_encodings_with_exact_low_byte_contract() {
        let nzc = ThumbLifter::partial_nzc_flags();
        for (op, expected_shift) in [
            (0b0010_u16, ShiftOp::Lsl),
            (0b0011, ShiftOp::Lsr),
            (0b0100, ShiftOp::Asr),
            (0b0111, ShiftOp::Ror),
        ] {
            for rdn in 0_u8..8 {
                for rs in 0_u8..8 {
                    let raw = 0x4000_u16 | (op << 6) | (u16::from(rs) << 3) | u16::from(rdn);
                    let result = lift(&raw.to_le_bytes());
                    assert_eq!(result.bytes_consumed, 2, "raw={raw:#06x}");
                    assert!(
                        matches!(
                            result.ops.as_slice(),
                            [SmirOp {
                                kind: OpKind::ArmRegShift {
                                    dst,
                                    src,
                                    amount: SrcOperand::Reg(amount),
                                    shift,
                                    width: OpWidth::W32,
                                    flags,
                                },
                                ..
                            }] if *dst == ThumbLifter::reg(rdn)
                                && *src == ThumbLifter::reg(rdn)
                                && *amount == ThumbLifter::reg(rs)
                                && *shift == expected_shift
                                && *flags == nzc
                        ),
                        "raw={raw:#06x}: {result:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn lifts_all_t32_register_shift_encodings_with_independent_registers_and_flags() {
        let nzc = ThumbLifter::partial_nzc_flags();
        for (kind, expected_shift) in [
            (0_u16, ShiftOp::Lsl),
            (1, ShiftOp::Lsr),
            (2, ShiftOp::Asr),
            (3, ShiftOp::Ror),
        ] {
            for setflags in [false, true] {
                let op1 = (kind << 1) | u16::from(setflags);
                for rd in 0_u8..16 {
                    for rn in 0_u8..16 {
                        for rs in 0_u8..16 {
                            let hw1 = 0xfa00_u16 | (op1 << 4) | u16::from(rn);
                            let hw2 = 0xf000_u16 | (u16::from(rd) << 8) | u16::from(rs);
                            let [a, b] = hw1.to_le_bytes();
                            let [c, d] = hw2.to_le_bytes();
                            let bytes = [a, b, c, d];
                            let mut lifter = ThumbLifter::new();
                            let mut ctx = LiftContext::new(SourceArch::Thumb);
                            let lifted = lifter.lift_insn(0x1000, &bytes, &mut ctx);

                            if rd == 15 || rn == 15 || rs == 15 {
                                assert!(
                                    matches!(lifted, Err(LiftError::Unsupported { .. })),
                                    "PC-bearing T32 shift escaped: {bytes:02x?} {lifted:?}"
                                );
                                continue;
                            }

                            let result = lifted.unwrap_or_else(|error| {
                                panic!("T32 shift {bytes:02x?} failed: {error}")
                            });
                            let expected_flags = if setflags { nzc } else { FlagUpdate::None };
                            assert_eq!(result.bytes_consumed, 4, "raw={bytes:02x?}");
                            assert!(
                                matches!(
                                    result.ops.as_slice(),
                                    [SmirOp {
                                        kind: OpKind::ArmRegShift {
                                            dst,
                                            src,
                                            amount: SrcOperand::Reg(amount),
                                            shift,
                                            width: OpWidth::W32,
                                            flags,
                                        },
                                        ..
                                    }] if *dst == ThumbLifter::reg(rd)
                                        && *src == ThumbLifter::reg(rn)
                                        && *amount == ThumbLifter::reg(rs)
                                        && *shift == expected_shift
                                        && *flags == expected_flags
                                ),
                                "raw={bytes:02x?}: {result:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn rejects_it_pc_memory_aliases_and_unmodeled_shifter_contracts() {
        let cases: &[&[u8]] = &[
            &[0x08, 0xbf],             // IT EQ
            &[0x78, 0x46],             // MOV r0,pc
            &[0x51, 0xf8, 0x04, 0x1f], // LDR r1,[r1,#4]! aliases writeback
            &[0x4f, 0xea, 0x31, 0x00], // RRX r0,r1
            &[0x4f, 0xfa, 0x93, 0xf2], // SXTB.W r2,r3,ROR #8
        ];
        for bytes in cases {
            let mut lifter = ThumbLifter::new();
            let mut ctx = LiftContext::new(SourceArch::Thumb);
            assert!(matches!(
                lifter.lift_insn(0x1000, bytes, &mut ctx),
                Err(LiftError::Unsupported { .. })
            ));
        }
    }

    #[test]
    fn lifts_t16_t32_literal_load_alignment_width_sign_add_subtract_and_wrap_matrix() {
        let t16 = lift(&[0x00, 0x48]);
        assert!(matches!(
            t16.ops.as_slice(),
            [SmirOp {
                kind: OpKind::Load {
                    dst,
                    addr: Address::Absolute(0x1004),
                    width: MemWidth::B4,
                    sign: SignExtend::Zero,
                },
                ..
            }] if *dst == ThumbLifter::reg(0)
        ));
        assert!(matches!(
            lift(&[0xff, 0x48]).ops.as_slice(),
            [SmirOp {
                kind: OpKind::Load {
                    addr: Address::Absolute(0x1400),
                    ..
                },
                ..
            }]
        ));

        let cases: &[(&[u8], u8, u64, MemWidth, SignExtend)] = &[
            (
                &[0xdf, 0xf8, 0x23, 0x01],
                0,
                0x1127,
                MemWidth::B4,
                SignExtend::Zero,
            ),
            (
                &[0x5f, 0xf8, 0x23, 0x11],
                1,
                0x0ee1,
                MemWidth::B4,
                SignExtend::Zero,
            ),
            (
                &[0x9f, 0xf8, 0x34, 0x22],
                2,
                0x1238,
                MemWidth::B1,
                SignExtend::Zero,
            ),
            (
                &[0x1f, 0xf8, 0x34, 0x32],
                3,
                0x0dd0,
                MemWidth::B1,
                SignExtend::Zero,
            ),
            (
                &[0xbf, 0xf8, 0x56, 0x44],
                4,
                0x145a,
                MemWidth::B2,
                SignExtend::Zero,
            ),
            (
                &[0x1f, 0xf9, 0x56, 0x54],
                5,
                0x0bae,
                MemWidth::B1,
                SignExtend::Sign,
            ),
            (
                &[0xbf, 0xf9, 0x78, 0x66],
                6,
                0x167c,
                MemWidth::B2,
                SignExtend::Sign,
            ),
            (
                &[0x3f, 0xf9, 0x78, 0x76],
                7,
                0x098c,
                MemWidth::B2,
                SignExtend::Sign,
            ),
            (
                &[0xdf, 0xf8, 0xff, 0x8f],
                8,
                0x2003,
                MemWidth::B4,
                SignExtend::Zero,
            ),
            (
                &[0x5f, 0xf8, 0xff, 0x9f],
                9,
                0x0005,
                MemWidth::B4,
                SignExtend::Zero,
            ),
        ];
        for (bytes, dst, address, width, sign) in cases {
            let result = lift(bytes);
            assert!(
                matches!(
                    result.ops.as_slice(),
                    [SmirOp {
                        kind: OpKind::Load {
                            dst: actual_dst,
                            addr: Address::Absolute(actual_address),
                            width: actual_width,
                            sign: actual_sign,
                        },
                        ..
                    }] if *actual_dst == ThumbLifter::reg(*dst)
                        && *actual_address == *address
                        && *actual_width == *width
                        && *actual_sign == *sign
                ),
                "{bytes:02x?}: {result:?}"
            );
        }

        let mut lifter = ThumbLifter::new();
        let mut ctx = LiftContext::new(SourceArch::Thumb);
        for (pc, bytes, expected) in [
            (0x1002, &[0x00, 0x48][..], 0x1004),
            (0xffff_fffe, &[0x01, 0x48][..], 4),
            (0xffff_fffe, &[0xdf, 0xf8, 0x04, 0x00][..], 4),
            (0xffff_fffe, &[0x5f, 0xf8, 0x04, 0x00][..], 0xffff_fffc),
        ] {
            let result = lifter.lift_insn(pc, bytes, &mut ctx).unwrap();
            assert!(matches!(
                result.ops.as_slice(),
                [SmirOp {
                    kind: OpKind::Load {
                        addr: Address::Absolute(address),
                        ..
                    },
                    ..
                }] if *address == expected
            ));
        }

        for bytes in [
            &[0xdf, 0xf8, 0x00, 0xf0][..], // literal load to PC is control flow
            &[0xcf, 0xf8, 0x00, 0x00][..], // PC-relative store is not admitted
        ] {
            assert!(
                matches!(
                    lifter.lift_insn(0x1000, bytes, &mut ctx),
                    Err(LiftError::Unsupported { .. })
                ),
                "{bytes:02x?}"
            );
        }
        assert!(matches!(
            lifter.lift_insn(u64::from(u32::MAX) + 1, &[0x00, 0x48], &mut ctx,),
            Err(LiftError::Unsupported { .. })
        ));
    }

    #[test]
    fn reports_t16_and_t32_incomplete_input_exactly() {
        let mut lifter = ThumbLifter::new();
        let mut ctx = LiftContext::new(SourceArch::Thumb);
        assert!(matches!(
            lifter.lift_insn(0x1000, &[0], &mut ctx),
            Err(LiftError::Incomplete {
                have: 1,
                need: 2,
                ..
            })
        ));
        assert!(matches!(
            lifter.lift_insn(0x1000, &[0x01, 0xeb, 0xc2], &mut ctx),
            Err(LiftError::Incomplete {
                have: 3,
                need: 4,
                ..
            })
        ));
    }

    #[test]
    fn block_lifting_advances_over_mixed_t16_t32_widths() {
        struct Memory {
            base: GuestAddr,
            bytes: Vec<u8>,
        }

        impl MemoryReader for Memory {
            fn read(
                &self,
                addr: GuestAddr,
                size: usize,
            ) -> Result<Vec<u8>, crate::smir::ir::memory::MemoryError> {
                let offset = (addr - self.base) as usize;
                if offset + size > self.bytes.len() {
                    return Err(crate::smir::ir::memory::MemoryError::OutOfBounds { addr });
                }
                Ok(self.bytes[offset..offset + size].to_vec())
            }
        }

        let memory = Memory {
            base: 0x1000,
            bytes: vec![
                0x88, 0x18, // ADDS r0,r1,r2 (T16)
                0x01, 0xeb, 0xc2, 0x00, // ADD.W r0,r1,r2,LSL #3 (T32)
                0x00, 0xe0, // B +0 (T16), target 0x100a
            ],
        };
        let mut lifter = ThumbLifter::new();
        let mut ctx = LiftContext::new(SourceArch::Thumb);
        let block = lifter.lift_block(0x1000, &memory, &mut ctx).unwrap();

        assert_eq!(block.ops.len(), 2);
        assert_eq!(block.ops[0].guest_pc, 0x1000);
        assert_eq!(block.ops[1].guest_pc, 0x1002);
        assert!(matches!(
            block.terminator,
            Terminator::Branch { target } if target == ctx.get_or_create_block(0x100a)
        ));
    }

    #[test]
    fn thumb_block_materializes_only_a_foldable_branch_condition() {
        struct Memory {
            base: GuestAddr,
            bytes: Vec<u8>,
        }

        impl MemoryReader for Memory {
            fn read(
                &self,
                addr: GuestAddr,
                size: usize,
            ) -> Result<Vec<u8>, crate::smir::ir::memory::MemoryError> {
                let offset = (addr - self.base) as usize;
                if offset + size > self.bytes.len() {
                    return Err(crate::smir::ir::memory::MemoryError::OutOfBounds { addr });
                }
                Ok(self.bytes[offset..offset + size].to_vec())
            }
        }

        let memory = Memory {
            base: 0x1000,
            bytes: vec![0x01, 0xd1], // BNE +2.
        };
        let mut lifter = ThumbLifter::new();
        let mut ctx = LiftContext::new(SourceArch::Thumb);
        let block = lifter.lift_block(0x1000, &memory, &mut ctx).unwrap();
        let taken = ctx.get_or_create_block(0x1006);
        let not_taken = ctx.get_or_create_block(0x1002);

        assert!(matches!(
            block.ops.as_slice(),
            [SmirOp {
                guest_pc: 0x1000,
                kind: OpKind::TestCondition {
                    dst,
                    cond: Condition::Ne,
                },
                ..
            }] if matches!(dst, VReg::Virtual(_))
        ));
        assert!(matches!(
            block.terminator,
            Terminator::CondBranch {
                cond: VReg::Virtual(_),
                true_target,
                false_target,
            } if true_target == taken && false_target == not_taken
        ));
    }

    #[test]
    fn thumb_block_keeps_cbz_as_a_register_condition_without_flag_materialization() {
        struct Memory([u8; 2]);

        impl MemoryReader for Memory {
            fn read(
                &self,
                addr: GuestAddr,
                size: usize,
            ) -> Result<Vec<u8>, crate::smir::ir::memory::MemoryError> {
                if addr != 0x1000 || size != 2 {
                    return Err(crate::smir::ir::memory::MemoryError::OutOfBounds { addr });
                }
                Ok(self.0.to_vec())
            }
        }

        let mut lifter = ThumbLifter::new();
        let mut ctx = LiftContext::new(SourceArch::Thumb);
        let block = lifter
            .lift_block(0x1000, &Memory([0x08, 0xb1]), &mut ctx)
            .unwrap(); // CBZ r0,+2.
        let nonzero = ctx.get_or_create_block(0x1002);
        let zero = ctx.get_or_create_block(0x1006);

        assert!(block.ops.is_empty());
        assert!(matches!(
            block.terminator,
            Terminator::CondBranch {
                cond: VReg::Arch(ArchReg::Arm(ArmReg::X(0))),
                true_target,
                false_target,
            } if true_target == nonzero && false_target == zero
        ));
    }
}

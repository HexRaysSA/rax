//! AArch32 (A32/ARM-state) instruction lifter.
//!
//! A32 scalar integer instructions use the same 32-bit SMIR operations and
//! architectural NZCV positions as AArch64.  This lifter deliberately shares
//! the mature scalar operation construction in [`super::aarch64`] while
//! enforcing A32-specific invariants before delegation:
//!
//! - r13 and r14 remain ordinary identity-mapped GPRs (`X13`/`X14`), not the
//!   AArch64 host SP/LR aliases;
//! - r15 data-register reads/writes, predicated data operations, RRX, and the
//!   LSR/ASR-#0 encodings remain fail-closed until their pipeline/conditional/
//!   shifter semantics can be represented without hidden native state;
//! - the complete 16-opcode A32 data-processing register-shifted-register
//!   space uses one compound SMIR operation with an exact low-byte count,
//!   read-before-write aliasing, shifter carry, and arithmetic NZCV contract;
//! - scalar LDM/STM and PUSH/POP forms without r15, user-bank transfer, or
//!   constrained base/list aliases expand into ordered B4 helper operations;
//! - literal scalar loads freeze the architectural `PC + 8` effective address
//!   into W32 absolute-address IR, including subtracting and wrapping forms;
//! - immediate/scaled-register LDRD/STRD forms over an even R0-R13 pair use
//!   pair memory IR so a second-word load fault cannot publish either result;
//! - unconditional and condition-code A32 branch targets use the architectural
//!   `PC + 8` base and become explicit SMIR control-flow edges; all PC
//!   arithmetic wraps modulo 2^32;
//! - BX over r0-r14 becomes a register-indirect SMIR terminator whose
//!   interworking state change is handled by the gated runtime exit path;
//! - BLX immediate/register forms preserve the return-state link bit and carry
//!   the callee execution state explicitly; BLX LR snapshots old LR before the
//!   link write;
//! - A32-only reverse-subtract, multiply-accumulate, and MOVW/MOVT forms are
//!   translated explicitly.

use std::collections::HashSet;

use crate::isa::arm::decoder::{
    Aarch32Decoder, AddressingMode, Condition as ArmCondition, DecodedInsn, MemOffset, MemOperand,
    Mnemonic, Operand, ShiftType,
};
use crate::smir::ir::flags::FlagUpdate;
use crate::smir::ir::memory::MemoryError;
use crate::smir::ir::ops::{ArmDpRegShiftKind, OpKind, SmirOp};
use crate::smir::ir::types::{
    Address, ArchReg, ArmReg, BlockId, Condition, DispSize, FunctionId, GuestAddr, MemWidth, OpId,
    OpWidth, ShiftOp, SignExtend, SourceArch, SrcOperand, VReg,
};
use crate::smir::ir::{
    CallTarget, CallingConv, FunctionAttrs, SmirBlock, SmirFunction, Terminator, TrapKind,
};
use crate::smir::lift::aarch64::Aarch64Lifter;
use crate::smir::lift::{
    ControlFlow, LiftContext, LiftError, LiftResult, MemoryReader, SmirLifter,
};

/// Fail-closed A32 scalar lifter.
pub struct Aarch32Lifter {
    shared: Aarch64Lifter,
}

impl Aarch32Lifter {
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
            mnemonic: "A32 guest PC outside the 32-bit address space".to_string(),
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
            .map_err(|_| LiftError::Internal("A32 instruction length exceeds u32".to_string()))?;
        Ok(u64::from(Self::pc32(pc)?.wrapping_add(bytes)))
    }

    fn operand_src(operand: &Operand) -> Result<SrcOperand, LiftError> {
        match operand {
            Operand::Reg(reg) if reg.num < 15 => Ok(SrcOperand::Reg(Self::reg(reg.num))),
            Operand::Imm(imm) => Ok(SrcOperand::Imm(imm.effective_value())),
            Operand::ShiftedReg(shifted)
                if shifted.reg.num < 15
                    && shifted.shift_type != ShiftType::RRX
                    && matches!(
                        shifted.immediate_amount(),
                        Some(amount)
                            if !(amount == 0
                                && matches!(shifted.shift_type, ShiftType::LSR | ShiftType::ASR))
                    ) =>
            {
                let amount = shifted
                    .immediate_amount()
                    .expect("guard requires immediate A32 scalar shift");
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
                "unsupported A32 scalar source operand".to_string(),
            )),
        }
    }

    fn rejects_hidden_state(insn: &DecodedInsn) -> bool {
        // A condition-code B has no predicated data effects: it is represented
        // directly as a two-edge SMIR terminator. Every other conditional A32
        // instruction still requires instruction-level commit suppression.
        if insn.cond.is_some() && insn.mnemonic != Mnemonic::B {
            return true;
        }
        insn.operands.iter().any(|operand| match operand {
            Operand::Reg(reg) => reg.num >= 15,
            Operand::ShiftedReg(shifted) => {
                shifted.reg.num >= 15
                    || shifted.shift_type == ShiftType::RRX
                    || matches!(shifted.amount_register(), Some(reg) if reg.num >= 15)
                    || matches!(
                        shifted.immediate_amount(),
                        Some(0) if matches!(shifted.shift_type, ShiftType::LSR | ShiftType::ASR)
                    )
            }
            Operand::Mem(mem) => {
                mem.base.num >= 15
                    || match &mem.offset {
                        MemOffset::None | MemOffset::Imm(_) => false,
                        MemOffset::Reg(reg) => reg.num >= 15,
                        MemOffset::ShiftedReg(shifted) => {
                            shifted.reg.num >= 15
                                || shifted.shift_type == ShiftType::RRX
                                || shifted.amount_register().is_some()
                                || matches!(
                                    shifted.immediate_amount(),
                                    Some(0)
                                        if matches!(
                                            shifted.shift_type,
                                            ShiftType::LSR | ShiftType::ASR | ShiftType::ROR
                                        )
                                )
                        }
                        MemOffset::ExtendedReg(extended) => extended.reg.num >= 15,
                    }
            }
            _ => false,
        })
    }

    /// Lift the complete A32 data-processing register-shifted-register space.
    fn lift_dp_register_shift(
        insn: &DecodedInsn,
        pc: GuestAddr,
        ops: &mut Vec<SmirOp>,
    ) -> Result<bool, LiftError> {
        if insn.state != crate::isa::arm::ExecutionState::Aarch32
            || (insn.raw >> 25) & 0x7 != 0
            || (insn.raw >> 4) & 1 == 0
            || (insn.raw >> 7) & 1 != 0
        {
            return Ok(false);
        }

        let opcode = ((insn.raw >> 21) & 0xf) as u8;
        let kind =
            ArmDpRegShiftKind::from_opcode(opcode).expect("four-bit A32 data-processing opcode");
        let encoded_s = (insn.raw >> 20) & 1 != 0;
        let expected_mnemonic = match (kind, encoded_s) {
            (ArmDpRegShiftKind::And, false) => Mnemonic::AND,
            (ArmDpRegShiftKind::And, true) => Mnemonic::ANDS,
            (ArmDpRegShiftKind::Eor, false) => Mnemonic::EOR,
            (ArmDpRegShiftKind::Eor, true) => Mnemonic::EORS,
            (ArmDpRegShiftKind::Sub, false) => Mnemonic::SUB,
            (ArmDpRegShiftKind::Sub, true) => Mnemonic::SUBS,
            (ArmDpRegShiftKind::Rsb, false) => Mnemonic::RSB,
            (ArmDpRegShiftKind::Rsb, true) => Mnemonic::RSBS,
            (ArmDpRegShiftKind::Add, false) => Mnemonic::ADD,
            (ArmDpRegShiftKind::Add, true) => Mnemonic::ADDS,
            (ArmDpRegShiftKind::Adc, false) => Mnemonic::ADC,
            (ArmDpRegShiftKind::Adc, true) => Mnemonic::ADCS,
            (ArmDpRegShiftKind::Sbc, false) => Mnemonic::SBC,
            (ArmDpRegShiftKind::Sbc, true) => Mnemonic::SBCS,
            (ArmDpRegShiftKind::Rsc, false) => Mnemonic::RSC,
            (ArmDpRegShiftKind::Rsc, true) => Mnemonic::RSCS,
            (ArmDpRegShiftKind::Tst, _) => Mnemonic::TST,
            (ArmDpRegShiftKind::Teq, _) => Mnemonic::TEQ,
            (ArmDpRegShiftKind::Cmp, _) => Mnemonic::CMP,
            (ArmDpRegShiftKind::Cmn, _) => Mnemonic::CMN,
            (ArmDpRegShiftKind::Orr, false) => Mnemonic::ORR,
            (ArmDpRegShiftKind::Orr, true) => Mnemonic::ORRS,
            (ArmDpRegShiftKind::Mov, false) => Mnemonic::MOV,
            (ArmDpRegShiftKind::Mov, true) => Mnemonic::MOVS,
            (ArmDpRegShiftKind::Bic, false) => Mnemonic::BIC,
            (ArmDpRegShiftKind::Bic, true) => Mnemonic::BICS,
            (ArmDpRegShiftKind::Mvn, false) => Mnemonic::MVN,
            (ArmDpRegShiftKind::Mvn, true) => Mnemonic::MVNS,
        };
        if insn.mnemonic != expected_mnemonic {
            return Ok(false);
        }
        let encoded_rn = ((insn.raw >> 16) & 0xf) as u8;
        let encoded_rd = ((insn.raw >> 12) & 0xf) as u8;

        let (dst, rn, shifted) = match (kind.writes_result(), kind.uses_rn()) {
            (true, true) => {
                let [
                    Operand::Reg(rd),
                    Operand::Reg(rn),
                    Operand::ShiftedReg(shifted),
                ] = insn.operands.as_slice()
                else {
                    return Err(LiftError::Internal(
                        "malformed A32 register-shifted data-processing operands".to_string(),
                    ));
                };
                (Some(rd), Some(rn), shifted)
            }
            (true, false) => {
                let [Operand::Reg(rd), Operand::ShiftedReg(shifted)] = insn.operands.as_slice()
                else {
                    return Err(LiftError::Internal(
                        "malformed A32 register-shifted move operands".to_string(),
                    ));
                };
                (Some(rd), None, shifted)
            }
            (false, true) => {
                let [Operand::Reg(rn), Operand::ShiftedReg(shifted)] = insn.operands.as_slice()
                else {
                    return Err(LiftError::Internal(
                        "malformed A32 register-shifted test operands".to_string(),
                    ));
                };
                (None, Some(rn), shifted)
            }
            (false, false) => unreachable!(),
        };

        let Some(rs) = shifted.amount_register() else {
            return Ok(false);
        };
        let fixed_fields_valid =
            (kind.writes_result() || encoded_rd == 0) && (kind.uses_rn() || encoded_rn == 0);
        let flags_valid = if kind.writes_result() {
            insn.sets_flags == encoded_s
        } else {
            encoded_s && insn.sets_flags
        };
        if !fixed_fields_valid
            || !flags_valid
            || dst.is_some_and(|reg| reg.num >= 15)
            || rn.is_some_and(|reg| reg.num >= 15)
            || shifted.reg.num >= 15
            || rs.num >= 15
            || shifted.shift_type == ShiftType::RRX
        {
            return Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: "A32 register-shifted data processing uses reserved fields or PC"
                    .to_string(),
            });
        }

        let shift = match shifted.shift_type {
            ShiftType::LSL => crate::smir::ir::types::ShiftOp::Lsl,
            ShiftType::LSR => crate::smir::ir::types::ShiftOp::Lsr,
            ShiftType::ASR => crate::smir::ir::types::ShiftOp::Asr,
            ShiftType::ROR => crate::smir::ir::types::ShiftOp::Ror,
            ShiftType::RRX => unreachable!(),
        };
        let flags = if encoded_s || !kind.writes_result() {
            if kind.is_logical() {
                FlagUpdate::Specific(
                    crate::smir::ir::flags::FlagSet::SF
                        .union(crate::smir::ir::flags::FlagSet::ZF)
                        .union(crate::smir::ir::flags::FlagSet::CF),
                )
            } else {
                FlagUpdate::Specific(crate::smir::ir::flags::FlagSet::NZCV)
            }
        } else {
            FlagUpdate::None
        };
        Self::push(
            ops,
            pc,
            OpKind::ArmDpRegShift {
                kind,
                dst: dst.map(|reg| Self::reg(reg.num)),
                rn: rn.map(|reg| Self::reg(reg.num)),
                rm: Self::reg(shifted.reg.num),
                rs: Self::reg(rs.num),
                shift,
                flags,
            },
        );
        Ok(true)
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
                    mnemonic: "A32 conditional branch uses reserved AL/NV condition".to_string(),
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
        let [Operand::Reg(rt), Operand::Mem(mem)] = insn.operands.as_slice() else {
            return Ok(None);
        };
        let MemOperand {
            base,
            offset: MemOffset::Imm(offset),
            mode: AddressingMode::Offset,
        } = mem
        else {
            return Ok(None);
        };
        if rt.num >= 15 || base.num != 15 {
            return Ok(None);
        }
        if insn.cond.is_some() {
            return Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: "predicated A32 literal load".to_string(),
            });
        }
        let address = Self::pc32(pc)?.wrapping_add(8).wrapping_add(*offset as u32);
        Ok(Some(OpKind::Load {
            dst: Self::reg(rt.num),
            addr: Address::Absolute(u64::from(address)),
            width,
            sign,
        }))
    }

    fn shift_op(shift: ShiftType) -> Result<ShiftOp, LiftError> {
        match shift {
            ShiftType::LSL => Ok(ShiftOp::Lsl),
            ShiftType::LSR => Ok(ShiftOp::Lsr),
            ShiftType::ASR => Ok(ShiftOp::Asr),
            ShiftType::ROR => Ok(ShiftOp::Ror),
            ShiftType::RRX => Err(LiftError::Internal(
                "A32 memory RRX escaped the hidden-state gate".to_string(),
            )),
        }
    }

    fn memory_writeback(insn: &DecodedInsn, mem: &MemOperand) -> Result<Option<OpKind>, LiftError> {
        if mem.mode == AddressingMode::Offset {
            return Ok(None);
        }

        let base = Self::reg(mem.base.num);
        let (subtract, src2) = match &mem.offset {
            MemOffset::None => return Ok(None),
            MemOffset::Imm(offset) if *offset < 0 => (true, SrcOperand::Imm(offset.wrapping_neg())),
            MemOffset::Imm(offset) => (false, SrcOperand::Imm(*offset)),
            MemOffset::Reg(index) => (
                ((insn.raw >> 23) & 1) == 0,
                SrcOperand::Reg(Self::reg(index.num)),
            ),
            MemOffset::ShiftedReg(shifted) => {
                let amount = shifted.immediate_amount().ok_or_else(|| {
                    LiftError::Internal(
                        "A32 memory offset has register-specified shift".to_string(),
                    )
                })?;
                (
                    ((insn.raw >> 23) & 1) == 0,
                    SrcOperand::Shifted {
                        reg: Self::reg(shifted.reg.num),
                        shift: Self::shift_op(shifted.shift_type)?,
                        amount,
                    },
                )
            }
            MemOffset::ExtendedReg(_) => {
                return Err(LiftError::Internal(
                    "A32 memory extended-register offset".to_string(),
                ));
            }
        };
        let kind = if subtract {
            OpKind::Sub {
                dst: base,
                src1: base,
                src2,
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            }
        } else {
            OpKind::Add {
                dst: base,
                src1: base,
                src2,
                width: OpWidth::W32,
                flags: FlagUpdate::None,
            }
        };
        Ok(Some(kind))
    }

    fn memory_address(
        insn: &DecodedInsn,
        mem: &MemOperand,
        pc: GuestAddr,
    ) -> Result<Address, LiftError> {
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
            MemOffset::Reg(index) if ((insn.raw >> 23) & 1) != 0 => Ok(Address::BaseIndexScale {
                base: Some(base),
                index: Self::reg(index.num),
                scale: 1,
                disp: 0,
                disp_size: DispSize::Auto,
            }),
            MemOffset::ShiftedReg(shifted)
                if ((insn.raw >> 23) & 1) != 0
                    && shifted.shift_type == ShiftType::LSL
                    && matches!(shifted.immediate_amount(), Some(amount) if amount <= 3) =>
            {
                let amount = shifted
                    .immediate_amount()
                    .expect("guard requires immediate A32 memory shift");
                Ok(Address::BaseIndexScale {
                    base: Some(base),
                    index: Self::reg(shifted.reg.num),
                    scale: 1 << amount,
                    disp: 0,
                    disp_size: DispSize::Auto,
                })
            }
            _ => Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: "A32 pre/offset register address not representable without a temporary"
                    .to_string(),
            }),
        }
    }

    fn lift_memory(
        &self,
        insn: &DecodedInsn,
        pc: GuestAddr,
        ops: &mut Vec<SmirOp>,
    ) -> Result<(), LiftError> {
        let Some((is_load, width, sign)) = Self::memory_kind(insn.mnemonic) else {
            return Err(LiftError::Internal(
                "invalid A32 scalar memory mnemonic".to_string(),
            ));
        };
        let [Operand::Reg(rt), Operand::Mem(mem)] = insn.operands.as_slice() else {
            return Err(LiftError::Internal(
                "invalid A32 scalar memory operands".to_string(),
            ));
        };
        let writeback = Self::memory_writeback(insn, mem)?;
        if is_load && writeback.is_some() && rt.num == mem.base.num {
            return Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: "A32 load writeback aliases its destination".to_string(),
            });
        }
        let addr = Self::memory_address(insn, mem, pc)?;
        let kind = if is_load {
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
        };
        Self::push(ops, pc, kind);
        // Both pre- and post-index writeback follow the helper access. A helper
        // fault exits from the memory op, so the writeback remains uncommitted.
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
        let [Operand::Reg(rt), Operand::Mem(mem)] = insn.operands.as_slice() else {
            return Err(LiftError::Internal(
                "invalid A32 double-transfer operands".to_string(),
            ));
        };
        if rt.num >= 14 || rt.num & 1 != 0 {
            return Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: "A32 double transfer requires an even R0-R13 pair".to_string(),
            });
        }
        let is_load = insn.mnemonic == Mnemonic::LDP;
        let rt2 = rt.num + 1;
        let writeback = Self::memory_writeback(insn, mem)?;
        if writeback.is_some() && (mem.base.num == rt.num || mem.base.num == rt2) {
            return Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: "A32 double transfer has a constrained base/pair alias".to_string(),
            });
        }
        let addr = Self::memory_address(insn, mem, pc)?;
        Self::push(
            ops,
            pc,
            if is_load {
                OpKind::LoadPair {
                    dst1: Self::reg(rt.num),
                    dst2: Self::reg(rt2),
                    addr,
                    width: MemWidth::B4,
                }
            } else {
                OpKind::StorePair {
                    src1: Self::reg(rt.num),
                    src2: Self::reg(rt2),
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
                "invalid A32 multiple-transfer mnemonic".to_string(),
            ));
        };
        let push_pop = matches!(insn.mnemonic, Mnemonic::PUSH | Mnemonic::POP);
        let (base_num, list) = match insn.operands.as_slice() {
            [Operand::RegList(list)] if push_pop => (13, list),
            [Operand::Reg(base), Operand::RegList(list)] if !push_pop => (base.num, list),
            _ => {
                return Err(LiftError::Internal(
                    "invalid A32 multiple-transfer operands".to_string(),
                ));
            }
        };
        let mask = list.mask;
        let writeback = push_pop || ((insn.raw >> 21) & 1) != 0;

        if base_num >= 15 || mask == 0 || list.contains(15) || ((insn.raw >> 22) & 1) != 0 {
            return Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: "A32 multiple transfer requires PC, user-bank, or empty-list semantics"
                    .to_string(),
            });
        }
        if (is_load && list.contains(base_num))
            || (!is_load && writeback && list.contains(base_num))
        {
            return Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: "A32 multiple transfer has a constrained base/list alias".to_string(),
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
            ADD | ADDS | ADC | ADCS | SUB | SUBS | SBC | SBCS | CMP | CMN | CLZ | RBIT | REV
            | REV16 | UDIV | SDIV | NOP => true,
            MOV => {
                !insn.sets_flags && !matches!(insn.operands.get(1), Some(Operand::ShiftedReg(_)))
            }
            AND | ORR | EOR | BIC | MVN | MUL => !insn.sets_flags,
            _ => false,
        }
    }

    fn bitfield_fields(insn: &DecodedInsn, pc: GuestAddr) -> Result<(u8, u8, u8), LiftError> {
        let rn = (insn.raw & 0xf) as u8;
        let lsb = ((insn.raw >> 7) & 0x1f) as u8;
        let encoded_width = ((insn.raw >> 16) & 0x1f) as u8;
        if rn >= 15 && insn.mnemonic != Mnemonic::BFC {
            return Err(LiftError::Unsupported {
                addr: pc,
                mnemonic: "A32 bitfield source PC".to_string(),
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
                    "A32 {:?} requires PC, predication, or special shifter state",
                    insn.mnemonic
                ),
            });
        }

        let mut ops = Vec::new();
        if Self::lift_dp_register_shift(insn, pc, &mut ops)? {
            return Ok((ops, ControlFlow::Fallthrough));
        }
        if Self::shared_scalar_mnemonic(insn) {
            return self.shared.lift_insn_inner(insn, pc, ctx);
        }

        let control = match insn.mnemonic {
            Mnemonic::LDR
            | Mnemonic::LDRB
            | Mnemonic::LDRH
            | Mnemonic::LDRSB
            | Mnemonic::LDRSH
            | Mnemonic::STR
            | Mnemonic::STRB
            | Mnemonic::STRH => {
                self.lift_memory(insn, pc, &mut ops)?;
                ControlFlow::Fallthrough
            }
            Mnemonic::LDP | Mnemonic::STP => {
                self.lift_double_memory(insn, pc, &mut ops)?;
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
                self.lift_multiple_memory(insn, pc, &mut ops)?;
                ControlFlow::Fallthrough
            }
            Mnemonic::MOV if !insn.sets_flags => {
                let [Operand::Reg(rd), Operand::ShiftedReg(shifted)] = insn.operands.as_slice()
                else {
                    return Err(LiftError::Internal(
                        "invalid A32 shifted MOV operands".to_string(),
                    ));
                };
                let dst = Self::reg(rd.num);
                let src = Self::reg(shifted.reg.num);
                let amount =
                    SrcOperand::Imm(i64::from(shifted.immediate_amount().ok_or_else(|| {
                        LiftError::Internal(
                            "A32 MOV register shift escaped dedicated lifting".to_string(),
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
                    insn.operands.first(),
                    insn.operands.get(1),
                    insn.operands.get(2),
                ) else {
                    return Err(LiftError::Internal("invalid A32 RSB operands".to_string()));
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
                            flags: if insn.sets_flags {
                                FlagUpdate::All
                            } else {
                                FlagUpdate::None
                            },
                        },
                    ),
                    SrcOperand::Imm(imm) if !insn.sets_flags => {
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
                    SrcOperand::Shifted { .. } if !insn.sets_flags && dst != rn => {
                        Self::push(
                            &mut ops,
                            pc,
                            OpKind::Mov {
                                dst,
                                src: Self::operand_src(operand2)?,
                                width: OpWidth::W32,
                            },
                        );
                        Self::push(
                            &mut ops,
                            pc,
                            OpKind::Sub {
                                dst,
                                src1: dst,
                                src2: SrcOperand::Reg(rn),
                                width: OpWidth::W32,
                                flags: FlagUpdate::None,
                            },
                        );
                    }
                    _ => {
                        return Err(LiftError::Unsupported {
                            addr: pc,
                            mnemonic: "A32 flag-setting or aliased shifted RSB".to_string(),
                        });
                    }
                }
                ControlFlow::Fallthrough
            }
            Mnemonic::MLA | Mnemonic::MLS if !insn.sets_flags => {
                let [
                    Operand::Reg(rd),
                    Operand::Reg(rm),
                    Operand::Reg(rs),
                    Operand::Reg(rn),
                ] = insn.operands.as_slice()
                else {
                    return Err(LiftError::Internal(
                        "invalid A32 multiply-accumulate operands".to_string(),
                    ));
                };
                let kind = if insn.mnemonic == Mnemonic::MLA {
                    OpKind::MulAdd {
                        dst: Self::reg(rd.num),
                        acc: Self::reg(rn.num),
                        src1: Self::reg(rm.num),
                        src2: Self::reg(rs.num),
                        width: OpWidth::W32,
                    }
                } else {
                    OpKind::MulSub {
                        dst: Self::reg(rd.num),
                        acc: Self::reg(rn.num),
                        src1: Self::reg(rm.num),
                        src2: Self::reg(rs.num),
                        width: OpWidth::W32,
                    }
                };
                Self::push(&mut ops, pc, kind);
                ControlFlow::Fallthrough
            }
            Mnemonic::UMULL | Mnemonic::SMULL if !insn.sets_flags => {
                let [
                    Operand::Reg(lo),
                    Operand::Reg(hi),
                    Operand::Reg(rm),
                    Operand::Reg(rs),
                ] = insn.operands.as_slice()
                else {
                    return Err(LiftError::Internal(
                        "invalid A32 long-multiply operands".to_string(),
                    ));
                };
                let args = (
                    Self::reg(lo.num),
                    Some(Self::reg(hi.num)),
                    Self::reg(rm.num),
                    SrcOperand::Reg(Self::reg(rs.num)),
                    OpWidth::W32,
                    FlagUpdate::None,
                );
                let kind = if insn.mnemonic == Mnemonic::UMULL {
                    OpKind::MulU {
                        dst_lo: args.0,
                        dst_hi: args.1,
                        src1: args.2,
                        src2: args.3,
                        width: args.4,
                        flags: args.5,
                    }
                } else {
                    OpKind::MulS {
                        dst_lo: args.0,
                        dst_hi: args.1,
                        src1: args.2,
                        src2: args.3,
                        width: args.4,
                        flags: args.5,
                    }
                };
                Self::push(&mut ops, pc, kind);
                ControlFlow::Fallthrough
            }
            Mnemonic::UBFX | Mnemonic::SBFX => {
                let Some(Operand::Reg(rd)) = insn.operands.first() else {
                    return Err(LiftError::Internal(
                        "invalid A32 bitfield-extract operands".to_string(),
                    ));
                };
                let (rn, lsb, encoded_width) = Self::bitfield_fields(insn, pc)?;
                let width_bits = encoded_width + 1;
                if u16::from(lsb) + u16::from(width_bits) > 32 {
                    return Err(LiftError::Unsupported {
                        addr: pc,
                        mnemonic: "A32 bitfield-extract bounds".to_string(),
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
                        sign_extend: insn.mnemonic == Mnemonic::SBFX,
                        op_width: OpWidth::W32,
                    },
                );
                ControlFlow::Fallthrough
            }
            Mnemonic::BFI | Mnemonic::BFC => {
                let Some(Operand::Reg(rd)) = insn.operands.first() else {
                    return Err(LiftError::Internal(
                        "invalid A32 bitfield-insert operands".to_string(),
                    ));
                };
                let (rn, lsb, msb) = Self::bitfield_fields(insn, pc)?;
                if msb < lsb {
                    return Err(LiftError::Unsupported {
                        addr: pc,
                        mnemonic: "A32 bitfield-insert bounds".to_string(),
                    });
                }
                let width_bits = msb - lsb + 1;
                let dst = Self::reg(rd.num);
                if insn.mnemonic == Mnemonic::BFC {
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
            Mnemonic::MOVZ => {
                let Some(Operand::Reg(rd)) = insn.operands.first() else {
                    return Err(LiftError::Internal("invalid A32 MOVW operands".to_string()));
                };
                let imm16 = (((insn.raw >> 16) & 0xf) << 12) | (insn.raw & 0xfff);
                Self::push(
                    &mut ops,
                    pc,
                    OpKind::Mov {
                        dst: Self::reg(rd.num),
                        src: SrcOperand::Imm(i64::from(imm16)),
                        width: OpWidth::W32,
                    },
                );
                ControlFlow::Fallthrough
            }
            Mnemonic::MOVK => {
                let Some(Operand::Reg(rd)) = insn.operands.first() else {
                    return Err(LiftError::Internal("invalid A32 MOVT operands".to_string()));
                };
                let dst = Self::reg(rd.num);
                let imm16 = (((insn.raw >> 16) & 0xf) << 12) | (insn.raw & 0xfff);
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
            Mnemonic::B => {
                let Some(Operand::Label(offset)) = insn.operands.first() else {
                    return Err(LiftError::Internal("invalid A32 B operands".to_string()));
                };
                let target = Self::add_pc_offset(pc, 8, *offset)?;
                if let Some(cond) = insn.cond {
                    ControlFlow::CondBranch {
                        cond: Self::branch_condition(cond, pc)?,
                        target,
                        fallthrough: Self::next_pc(pc, 4)?,
                    }
                } else {
                    ControlFlow::Branch { target }
                }
            }
            Mnemonic::BL => {
                let Some(Operand::Label(offset)) = insn.operands.first() else {
                    return Err(LiftError::Internal("invalid A32 BL operands".to_string()));
                };
                Self::push(
                    &mut ops,
                    pc,
                    OpKind::Mov {
                        dst: Self::reg(14),
                        src: SrcOperand::Imm(Self::next_pc(pc, 4)? as i64),
                        width: OpWidth::W32,
                    },
                );
                ControlFlow::Call {
                    target: CallTarget::GuestAddr(Self::add_pc_offset(pc, 8, *offset)?),
                }
            }
            Mnemonic::BLX => match insn.operands.first() {
                Some(Operand::Label(offset)) => {
                    Self::push(
                        &mut ops,
                        pc,
                        OpKind::Mov {
                            dst: Self::reg(14),
                            src: SrcOperand::Imm(Self::next_pc(pc, 4)? as i64),
                            width: OpWidth::W32,
                        },
                    );
                    ControlFlow::Call {
                        target: CallTarget::GuestAddrInterworking {
                            addr: Self::add_pc_offset(pc, 8, *offset)?,
                            thumb: true,
                        },
                    }
                }
                Some(Operand::Reg(rm)) => {
                    // BLX LR must consume the old LR before installing its return
                    // address. Preserve that data dependency explicitly in SMIR;
                    // other registers remain unchanged by the link write.
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
                            src: SrcOperand::Imm(Self::next_pc(pc, 4)? as i64),
                            width: OpWidth::W32,
                        },
                    );
                    ControlFlow::Call {
                        target: CallTarget::IndirectInterworking(target),
                    }
                }
                _ => {
                    return Err(LiftError::Internal("invalid A32 BLX operands".to_string()));
                }
            },
            Mnemonic::BX => {
                let Some(Operand::Reg(rm)) = insn.operands.first() else {
                    return Err(LiftError::Internal("invalid A32 BX operands".to_string()));
                };
                ControlFlow::IndirectBranch {
                    target: Self::reg(rm.num),
                }
            }
            _ => {
                return Err(LiftError::Unsupported {
                    addr: pc,
                    mnemonic: format!("A32 {:?}", insn.mnemonic),
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
}

impl Default for Aarch32Lifter {
    fn default() -> Self {
        Self::new()
    }
}

impl SmirLifter for Aarch32Lifter {
    fn source_arch(&self) -> SourceArch {
        SourceArch::Aarch32
    }

    fn lift_insn(
        &mut self,
        addr: GuestAddr,
        bytes: &[u8],
        ctx: &mut LiftContext,
    ) -> Result<LiftResult, LiftError> {
        Self::pc32(addr)?;
        if bytes.len() < 4 {
            return Err(LiftError::Incomplete {
                addr,
                have: bytes.len(),
                need: 4,
            });
        }
        let raw = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let insn = Aarch32Decoder::decode(raw).map_err(|_| LiftError::InvalidEncoding {
            addr,
            bytes: bytes[..4].to_vec(),
        })?;
        ctx.guest_pc = addr;
        let (ops, control) = self.lift_decoded(&insn, addr, ctx)?;
        Ok(Self::result(ops, 4, control))
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
            let bytes = mem
                .read(pc, 4)
                .map_err(|error| LiftError::MemoryError { addr: pc, error })?;
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
                ControlFlow::Return => Terminator::Return { values: Vec::new() },
                ControlFlow::IndirectBranch { target } => Terminator::IndirectBranch {
                    target,
                    possible_targets: Vec::new(),
                },
                ControlFlow::Trap { kind } => Terminator::Trap { kind },
                ControlFlow::Syscall => Terminator::Trap {
                    kind: TrapKind::SystemCall,
                },
                ControlFlow::CondBranchReg { .. } | ControlFlow::IndirectBranchMem { .. } => {
                    return Err(LiftError::Unsupported {
                        addr: insn_pc,
                        mnemonic: "A32 block terminator".to_string(),
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
            .map(|block| {
                block
                    .guest_pc
                    .wrapping_add((block.ops.len().max(1) * 4) as u64)
            })
            .max()
            .unwrap_or(entry.wrapping_add(4));
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
mod tests;

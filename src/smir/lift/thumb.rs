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
//!   IR, and T16 ADR into a constant, while other PC-bearing, empty-list,
//!   and constrained base/list forms fail closed;
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
        // ADR (T1), decoded as ADD Rd with the offset as a label: the
        // address, Align(PC + 4, 4) + imm32, is known when lifting.
        if let (Mnemonic::ADD, None, [Operand::Reg(rd), Operand::Label(offset)]) =
            (insn.mnemonic, insn.cond, insn.operands.as_slice())
        {
            let address = (Self::pc32(pc)?.wrapping_add(4) & !3).wrapping_add(*offset as u32);
            let mut ops = Vec::new();
            Self::push(
                &mut ops,
                pc,
                OpKind::Mov {
                    dst: Self::reg(rd.num),
                    src: SrcOperand::Imm(i64::from(address)),
                    width: OpWidth::W32,
                },
            );
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
mod tests;

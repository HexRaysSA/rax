//! AArch32 (A32) instruction decoder.
//!
//! This module decodes 32-bit ARM instructions (AArch32/A32).
//! All A32 instructions are 32 bits wide.

use super::{operand::*, Condition, DecodeError, DecodedInsn, Mnemonic, ShiftType};
use crate::arm::ExecutionState;

/// AArch32 instruction decoder.
pub struct Aarch32Decoder;

impl Aarch32Decoder {
    /// Decode a 32-bit AArch32 instruction.
    pub fn decode(raw: u32) -> Result<DecodedInsn, DecodeError> {
        // Extract condition code (bits 31:28)
        let cond_bits = ((raw >> 28) & 0xF) as u8;
        let cond = Condition::from_bits(cond_bits);

        // Unconditional instructions (cond = 0b1111)
        if cond_bits == 0b1111 {
            return Self::decode_unconditional(raw);
        }

        // Extract op1 (bits 27:25) and op (bit 4)
        let op1 = (raw >> 25) & 0x7;
        let op = (raw >> 4) & 1;

        let insn = match op1 {
            // 0b000: Data processing and misc
            0b000 => {
                // Check bits [7:4] to distinguish instruction types
                let op2 = (raw >> 4) & 0xF;
                if op2 == 0b1001 {
                    // Multiply instructions (bits [7:4] = 1001)
                    Self::decode_dp_misc(raw)?
                } else if (op2 & 0b1001) == 0b1001 {
                    // Extra load/store (bits [7:4] = 1x11 or 1xx1, but not 1001)
                    Self::decode_extra_load_store(raw)?
                } else {
                    // Data processing register/immediate shift
                    Self::decode_dp_misc(raw)?
                }
            }
            // 0b001: Data processing immediate (and MSR immediate)
            0b001 => Self::decode_dp_immediate(raw)?,
            // 0b010: Load/store word and unsigned byte (immediate)
            0b010 => Self::decode_load_store_word_byte(raw, false)?,
            // 0b011: Load/store word and unsigned byte (register) / media
            0b011 => {
                if op == 0 {
                    Self::decode_load_store_word_byte(raw, true)?
                } else {
                    Self::decode_media(raw)?
                }
            }
            // 0b100: Load/store multiple
            0b100 => Self::decode_load_store_multiple(raw)?,
            // 0b101: Branch / branch with link
            0b101 => Self::decode_branch(raw)?,
            // 0b110: Coprocessor load/store, 2-reg transfer
            0b110 => Self::decode_coprocessor_load_store(raw)?,
            // 0b111: Coprocessor data processing / SWI
            0b111 => {
                if (raw >> 24) & 1 == 1 {
                    Self::decode_svc(raw)?
                } else {
                    Self::decode_coprocessor_dp(raw)?
                }
            }
            _ => DecodedInsn::new(Mnemonic::UNKNOWN, ExecutionState::Aarch32, raw, 4),
        };

        // Add condition to non-AL instructions
        let insn = if cond != Condition::AL {
            insn.with_cond(cond)
        } else {
            insn
        };

        Ok(insn)
    }

    // =========================================================================
    // Unconditional Instructions
    // =========================================================================

    fn decode_unconditional(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let op1 = (raw >> 20) & 0xFF;

        match op1 >> 5 {
            // Memory hints, barriers, CLREX
            0b010 => Self::decode_hints_barriers(raw),
            // BLX (immediate)
            0b101 => Self::decode_blx_imm(raw),
            // Coprocessor
            0b110 | 0b111 => {
                // Handle as coprocessor with NV condition
                let insn = if (raw >> 24) & 1 == 1 {
                    Self::decode_svc(raw)?
                } else {
                    Self::decode_coprocessor_dp(raw)?
                };
                Ok(insn)
            }
            _ => Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            )),
        }
    }

    fn decode_hints_barriers(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let op1 = (raw >> 20) & 0x7F;
        let op2 = (raw >> 4) & 0xF;

        if op1 == 0b0110010 {
            // Barriers
            let mnemonic = match op2 {
                0b0100 => Mnemonic::DSB,
                0b0101 => Mnemonic::DMB,
                0b0110 => Mnemonic::ISB,
                _ => Mnemonic::UNDEFINED,
            };

            let option = BarrierOption::from_bits((raw & 0xF) as u8);

            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4)
                .with_operand(Operand::Barrier(option)));
        }

        if op1 == 0b0110001 && op2 == 0b0001 {
            // CLREX
            return Ok(DecodedInsn::new(
                Mnemonic::CLREX,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        // Hints: NOP, YIELD, WFE, WFI, SEV
        if op1 == 0b0010000 && (raw & 0xFFF0) == 0xF000 {
            let hint = raw & 0xFF;
            let mnemonic = match hint {
                0 => Mnemonic::NOP,
                1 => Mnemonic::YIELD,
                2 => Mnemonic::WFE,
                3 => Mnemonic::WFI,
                4 => Mnemonic::SEV,
                _ => Mnemonic::HINT,
            };

            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4));
        }

        Ok(DecodedInsn::new(
            Mnemonic::UNDEFINED,
            ExecutionState::Aarch32,
            raw,
            4,
        ))
    }

    fn decode_blx_imm(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let h = (raw >> 24) & 1;
        let imm24 = (raw & 0xFFFFFF) as i64;

        // Sign extend and shift
        let offset = if imm24 & (1 << 23) != 0 {
            ((imm24 | !0xFFFFFF) << 2) | (h << 1) as i64
        } else {
            (imm24 << 2) | (h << 1) as i64
        };

        Ok(
            DecodedInsn::new(Mnemonic::BLX, ExecutionState::Aarch32, raw, 4)
                .with_operand(Operand::Label(offset)),
        )
    }

    // =========================================================================
    // Data Processing and Miscellaneous
    // =========================================================================

    fn decode_dp_misc(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let op = (raw >> 20) & 0x1F;
        let op2 = (raw >> 4) & 0xF;

        // Check for special cases first
        if op == 0b10010 && op2 == 0b0001 {
            // BX
            return Self::decode_bx(raw);
        }

        if op == 0b10010 && op2 == 0b0011 {
            // BLX (register)
            return Self::decode_blx_reg(raw);
        }

        // CLZ: op = 0b10110, op2 = 0b0001
        if op == 0b10110 && op2 == 0b0001 {
            let rd = ((raw >> 12) & 0xF) as u8;
            let rm = (raw & 0xF) as u8;
            return Ok(
                DecodedInsn::new(Mnemonic::CLZ, ExecutionState::Aarch32, raw, 4)
                    .with_operand(Operand::Reg(Register::raw(rd, false, false)))
                    .with_operand(Operand::Reg(Register::raw(rm, false, false))),
            );
        }

        // Miscellaneous / halfword-multiply space: S=0 with a TST/TEQ/CMP/CMN
        // opcode (op == 10xx0). These are NOT data-processing comparisons.
        if (op & 0b11001) == 0b10000 {
            let rd = ((raw >> 12) & 0xF) as u8;
            let rn = ((raw >> 16) & 0xF) as u8;
            let rm = (raw & 0xF) as u8;
            if op2 == 0b0101 {
                // Saturating add/sub: QADD/QSUB/QDADD/QDSUB (Rd = sat(Rm op Rn))
                return Ok(
                    DecodedInsn::new(Mnemonic::A32_SAT_ADDSUB, ExecutionState::Aarch32, raw, 4)
                        .with_operand(Operand::Reg(Register::raw(rd, false, false)))
                        .with_operand(Operand::Reg(Register::raw(rm, false, false)))
                        .with_operand(Operand::Reg(Register::raw(rn, false, false))),
                );
            }
            if (op2 & 0b1001) == 0b1000 {
                // Halfword/word multiplies: SMLA/SMUL/SMLAW/SMULW/SMLAL<x><y>
                return Ok(
                    DecodedInsn::new(Mnemonic::A32_HMUL, ExecutionState::Aarch32, raw, 4)
                        .with_operand(Operand::Reg(Register::raw(rd, false, false))),
                );
            }
        }

        if op2 == 0b1001 {
            // Multiply instructions
            return Self::decode_multiply(raw);
        }

        if (op2 & 0b1001) == 0b1001 && op2 != 0b1001 {
            // Extra load/store
            return Self::decode_extra_load_store(raw);
        }

        // Data processing (register)
        Self::decode_dp_register(raw)
    }

    fn decode_dp_register(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let opcode = ((raw >> 21) & 0xF) as u8;
        let s = (raw >> 20) & 1;
        let rn = ((raw >> 16) & 0xF) as u8;
        let rd = ((raw >> 12) & 0xF) as u8;
        let shift_imm = ((raw >> 7) & 0x1F) as u8;
        let shift_type = ShiftType::from_bits(((raw >> 5) & 0x3) as u8);
        let rm = (raw & 0xF) as u8;

        let (mnemonic, uses_rn, writes_rd) = Self::dp_opcode_to_mnemonic(opcode, s == 1);

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4);

        if s == 1 && writes_rd {
            insn.sets_flags = true;
        }

        if writes_rd {
            insn = insn.with_operand(Operand::Reg(Register::raw(rd, false, false)));
        }

        if uses_rn {
            insn = insn.with_operand(Operand::Reg(Register::raw(rn, false, false)));
        }

        // Add shifted register operand
        let rm_reg = Register::raw(rm, false, false);

        if shift_imm == 0 && shift_type == ShiftType::LSL {
            insn = insn.with_operand(Operand::Reg(rm_reg));
        } else if shift_imm == 0 && shift_type == ShiftType::ROR {
            // RRX
            insn = insn.with_operand(Operand::ShiftedReg(ShiftedRegister::new(
                rm_reg,
                ShiftType::RRX,
                0,
            )));
        } else {
            insn = insn.with_operand(Operand::ShiftedReg(ShiftedRegister::new(
                rm_reg, shift_type, shift_imm,
            )));
        }

        Ok(insn)
    }

    fn decode_dp_immediate(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let opcode = ((raw >> 21) & 0xF) as u8;
        let s = (raw >> 20) & 1;
        let rn = ((raw >> 16) & 0xF) as u8;
        let rd = ((raw >> 12) & 0xF) as u8;
        let rotate = ((raw >> 8) & 0xF) as u8;
        let imm8 = (raw & 0xFF) as u32;

        // Check for hint instructions (NOP, YIELD, WFE, WFI, SEV)
        // Encoding: cond 0011 0010 0000 1111 0000 0000 hint
        // bits [27:20] = 0x32 = 0011 0010, Rn = 0, Rd = 15 (PC), rotate = 0
        // Note: opcode here is bits [24:21] = 1001, not the MSR opcode
        let bits_27_20 = (raw >> 20) & 0xFF;
        if bits_27_20 == 0x32 && rn == 0 && rd == 15 && rotate == 0 {
            let hint = imm8 & 0xFF;
            let mnemonic = match hint {
                0 => Mnemonic::NOP,
                1 => Mnemonic::YIELD,
                2 => Mnemonic::WFE,
                3 => Mnemonic::WFI,
                4 => Mnemonic::SEV,
                _ => Mnemonic::HINT,
            };
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4));
        }

        // 16-bit immediate moves occupy the S=0 slots of the TST/CMP opcodes:
        //   opcode 1000 (0011 0000) = MOVW (move wide), imm16 = imm4:imm12
        //   opcode 1010 (0011 0100) = MOVT (move top)
        // (MOVZ/MOVK mnemonics are reused; exec reads the imm fields from raw.)
        if s == 0 && (opcode == 0b1000 || opcode == 0b1010) {
            let m = if opcode == 0b1000 {
                Mnemonic::MOVZ
            } else {
                Mnemonic::MOVK
            };
            return Ok(DecodedInsn::new(m, ExecutionState::Aarch32, raw, 4)
                .with_operand(Operand::Reg(Register::raw(rd, false, false))));
        }

        // Decode immediate: rotate_right(imm8, rotate * 2)
        let imm = imm8.rotate_right((rotate * 2) as u32) as i64;

        let (mnemonic, uses_rn, writes_rd) = Self::dp_opcode_to_mnemonic(opcode, s == 1);

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4);

        if s == 1 && writes_rd {
            insn.sets_flags = true;
        }

        if writes_rd {
            insn = insn.with_operand(Operand::Reg(Register::raw(rd, false, false)));
        }

        if uses_rn {
            insn = insn.with_operand(Operand::Reg(Register::raw(rn, false, false)));
        }

        insn = insn.with_operand(Operand::Imm(Immediate::new(imm)));

        Ok(insn)
    }

    fn dp_opcode_to_mnemonic(opcode: u8, s: bool) -> (Mnemonic, bool, bool) {
        // Returns (mnemonic, uses_rn, writes_rd)
        match opcode {
            0b0000 => (if s { Mnemonic::ANDS } else { Mnemonic::AND }, true, true),
            0b0001 => (if s { Mnemonic::EORS } else { Mnemonic::EOR }, true, true),
            0b0010 => (if s { Mnemonic::SUBS } else { Mnemonic::SUB }, true, true),
            0b0011 => (if s { Mnemonic::RSBS } else { Mnemonic::RSB }, true, true),
            0b0100 => (if s { Mnemonic::ADDS } else { Mnemonic::ADD }, true, true),
            0b0101 => (if s { Mnemonic::ADCS } else { Mnemonic::ADC }, true, true),
            0b0110 => (if s { Mnemonic::SBCS } else { Mnemonic::SBC }, true, true),
            0b0111 => (if s { Mnemonic::RSCS } else { Mnemonic::RSC }, true, true),
            0b1000 => (Mnemonic::TST, true, false), // S is always 1
            0b1001 => (Mnemonic::TEQ, true, false),
            0b1010 => (Mnemonic::CMP, true, false),
            0b1011 => (Mnemonic::CMN, true, false),
            0b1100 => (if s { Mnemonic::ORRS } else { Mnemonic::ORR }, true, true),
            0b1101 => (if s { Mnemonic::MOVS } else { Mnemonic::MOV }, false, true),
            0b1110 => (if s { Mnemonic::BICS } else { Mnemonic::BIC }, true, true),
            0b1111 => (if s { Mnemonic::MVNS } else { Mnemonic::MVN }, false, true),
            _ => unreachable!(),
        }
    }

    fn decode_bx(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let rm = (raw & 0xF) as u8;

        Ok(
            DecodedInsn::new(Mnemonic::BX, ExecutionState::Aarch32, raw, 4)
                .with_operand(Operand::Reg(Register::raw(rm, false, false))),
        )
    }

    fn decode_blx_reg(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let rm = (raw & 0xF) as u8;

        Ok(
            DecodedInsn::new(Mnemonic::BLX, ExecutionState::Aarch32, raw, 4)
                .with_operand(Operand::Reg(Register::raw(rm, false, false))),
        )
    }

    // =========================================================================
    // Multiply Instructions
    // =========================================================================

    fn decode_multiply(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let op = (raw >> 21) & 0xF;
        let s = (raw >> 20) & 1;
        let rd = ((raw >> 16) & 0xF) as u8;
        let rn = ((raw >> 12) & 0xF) as u8;
        let rs = ((raw >> 8) & 0xF) as u8;
        let rm = (raw & 0xF) as u8;

        let (mnemonic, operands) = match op {
            0b0000 => {
                // MUL
                let m = if s == 1 {
                    Mnemonic::MULS
                } else {
                    Mnemonic::MUL
                };
                (m, vec![rd, rm, rs])
            }
            0b0001 => {
                // MLA
                let m = if s == 1 { Mnemonic::MLA } else { Mnemonic::MLA };
                (m, vec![rd, rm, rs, rn])
            }
            0b0100 => {
                // UMULL
                let m = if s == 1 {
                    Mnemonic::UMULLS
                } else {
                    Mnemonic::UMULL
                };
                (m, vec![rn, rd, rm, rs]) // RdLo, RdHi, Rm, Rs
            }
            0b0101 => {
                // UMLAL
                (Mnemonic::UMLAL, vec![rn, rd, rm, rs])
            }
            0b0110 => {
                // SMULL
                let m = if s == 1 {
                    Mnemonic::SMULLS
                } else {
                    Mnemonic::SMULL
                };
                (m, vec![rn, rd, rm, rs])
            }
            0b0111 => {
                // SMLAL
                (Mnemonic::SMLAL, vec![rn, rd, rm, rs])
            }
            0b0010 => {
                // UMAAL (RdHi, RdLo, Rm, Rs) -- no S variant
                (Mnemonic::UMAAL, vec![rn, rd, rm, rs])
            }
            0b0011 => {
                // MLS
                (Mnemonic::MLS, vec![rd, rm, rs, rn])
            }
            _ => (Mnemonic::UNKNOWN, vec![]),
        };

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4);

        if s == 1 {
            insn.sets_flags = true;
        }

        for reg_num in operands {
            insn = insn.with_operand(Operand::Reg(Register::raw(reg_num, false, false)));
        }

        Ok(insn)
    }

    // =========================================================================
    // Load/Store Instructions
    // =========================================================================

    fn decode_load_store_word_byte(raw: u32, reg_offset: bool) -> Result<DecodedInsn, DecodeError> {
        let p = (raw >> 24) & 1;
        let u = (raw >> 23) & 1;
        let b = (raw >> 22) & 1;
        let w = (raw >> 21) & 1;
        let l = (raw >> 20) & 1;
        let rn = ((raw >> 16) & 0xF) as u8;
        let rt = ((raw >> 12) & 0xF) as u8;

        // Determine mnemonic
        let mnemonic = match (l, b) {
            (0, 0) => Mnemonic::STR,
            (0, 1) => Mnemonic::STRB,
            (1, 0) => Mnemonic::LDR,
            (1, 1) => Mnemonic::LDRB,
            _ => unreachable!(),
        };

        // Calculate offset
        let offset: MemOffset = if reg_offset {
            let shift_imm = ((raw >> 7) & 0x1F) as u8;
            let shift_type = ShiftType::from_bits(((raw >> 5) & 0x3) as u8);
            let rm = (raw & 0xF) as u8;

            if shift_imm == 0 && shift_type == ShiftType::LSL {
                MemOffset::Reg(Register::raw(rm, false, false))
            } else {
                MemOffset::ShiftedReg(ShiftedRegister::new(
                    Register::raw(rm, false, false),
                    shift_type,
                    shift_imm,
                ))
            }
        } else {
            let imm12 = (raw & 0xFFF) as i64;
            let offset_val = if u == 1 { imm12 } else { -imm12 };
            MemOffset::Imm(offset_val)
        };

        // Determine addressing mode
        let mode = match (p, w) {
            (1, 0) => AddressingMode::Offset,
            (1, 1) => AddressingMode::PreIndex,
            _ => AddressingMode::PostIndex,
        };

        let mem = MemOperand {
            base: Register::raw(rn, false, false),
            offset,
            mode,
        };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4)
            .with_operand(Operand::Reg(Register::raw(rt, false, false)))
            .with_operand(Operand::Mem(mem)))
    }

    fn decode_extra_load_store(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let p = (raw >> 24) & 1;
        let u = (raw >> 23) & 1;
        let i = (raw >> 22) & 1;
        let w = (raw >> 21) & 1;
        let l = (raw >> 20) & 1;
        let rn = ((raw >> 16) & 0xF) as u8;
        let rt = ((raw >> 12) & 0xF) as u8;
        let op1 = (raw >> 5) & 0x3;
        let rm_or_imm = (raw & 0xF) as u8;
        let imm_hi = ((raw >> 8) & 0xF) as u8;

        let mnemonic = match (l, op1) {
            (1, 0b01) => Mnemonic::LDRH,
            (1, 0b10) => Mnemonic::LDRSB,
            (1, 0b11) => Mnemonic::LDRSH,
            (0, 0b01) => Mnemonic::STRH,
            _ => Mnemonic::UNKNOWN,
        };

        let offset = if i == 1 {
            let imm8 = ((imm_hi << 4) | rm_or_imm) as i64;
            let offset_val = if u == 1 { imm8 } else { -imm8 };
            MemOffset::Imm(offset_val)
        } else {
            MemOffset::Reg(Register::raw(rm_or_imm, false, false))
        };

        let mode = match (p, w) {
            (1, 0) => AddressingMode::Offset,
            (1, 1) => AddressingMode::PreIndex,
            _ => AddressingMode::PostIndex,
        };

        let mem = MemOperand {
            base: Register::raw(rn, false, false),
            offset,
            mode,
        };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4)
            .with_operand(Operand::Reg(Register::raw(rt, false, false)))
            .with_operand(Operand::Mem(mem)))
    }

    fn decode_load_store_multiple(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let p = (raw >> 24) & 1;
        let u = (raw >> 23) & 1;
        let s = (raw >> 22) & 1; // PSR & force user bit
        let w = (raw >> 21) & 1;
        let l = (raw >> 20) & 1;
        let rn = ((raw >> 16) & 0xF) as u8;
        let reg_list = (raw & 0xFFFF) as u16;

        // Determine mnemonic based on direction and incrementing
        let mnemonic = match (l, p, u) {
            // Load
            (1, 0, 1) => Mnemonic::LDMIA, // or LDMFD
            (1, 1, 1) => Mnemonic::LDMIB, // or LDMED
            (1, 0, 0) => Mnemonic::LDMDA, // or LDMFA
            (1, 1, 0) => Mnemonic::LDMDB, // or LDMEA
            // Store
            (0, 0, 1) => Mnemonic::STMIA, // or STMEA
            (0, 1, 1) => Mnemonic::STMIB, // or STMFA
            (0, 0, 0) => Mnemonic::STMDA, // or STMED
            (0, 1, 0) => Mnemonic::STMDB, // or STMFD
            _ => Mnemonic::UNKNOWN,
        };

        // Check for PUSH/POP aliases
        let mnemonic = if rn == 13 && w == 1 {
            match (l, p, u) {
                (1, 0, 1) => Mnemonic::POP,  // LDMIA SP!, {regs} = POP {regs}
                (0, 1, 0) => Mnemonic::PUSH, // STMDB SP!, {regs} = PUSH {regs}
                _ => mnemonic,
            }
        } else {
            mnemonic
        };

        let is_push_pop = matches!(mnemonic, Mnemonic::PUSH | Mnemonic::POP);

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4);

        // Add base register (not for PUSH/POP)
        if !is_push_pop {
            let base = Register::raw(rn, false, false);
            insn = insn.with_operand(Operand::Reg(base));
        }

        // Add register list
        insn = insn.with_operand(Operand::RegList(RegisterList::from_mask(reg_list)));

        Ok(insn)
    }

    // =========================================================================
    // Branch Instructions
    // =========================================================================

    fn decode_branch(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let l = (raw >> 24) & 1;
        let imm24 = (raw & 0xFFFFFF) as i64;

        // Sign extend and shift left by 2
        let offset = if imm24 & (1 << 23) != 0 {
            (imm24 | !0xFFFFFF) << 2
        } else {
            imm24 << 2
        };

        let mnemonic = if l == 1 { Mnemonic::BL } else { Mnemonic::B };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4)
            .with_operand(Operand::Label(offset)))
    }

    // =========================================================================
    // Coprocessor Instructions
    // =========================================================================

    fn decode_coprocessor_load_store(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let l = (raw >> 20) & 1;

        let mnemonic = if l == 1 { Mnemonic::LDC } else { Mnemonic::STC };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    fn decode_coprocessor_dp(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let op = (raw >> 4) & 1;

        if op == 0 {
            // CDP
            Ok(DecodedInsn::new(
                Mnemonic::CDP,
                ExecutionState::Aarch32,
                raw,
                4,
            ))
        } else {
            // MCR/MRC
            let l = (raw >> 20) & 1;
            let cp_num = ((raw >> 8) & 0xF) as u8;
            let op1 = ((raw >> 21) & 0x7) as u8;
            let crn = ((raw >> 16) & 0xF) as u8;
            let rt = ((raw >> 12) & 0xF) as u8;
            let crm = (raw & 0xF) as u8;
            let op2 = ((raw >> 5) & 0x7) as u8;

            let mnemonic = if l == 1 { Mnemonic::MRC } else { Mnemonic::MCR };

            Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4)
                .with_operand(Operand::Imm(Immediate::new(cp_num as i64)))
                .with_operand(Operand::Imm(Immediate::new(op1 as i64)))
                .with_operand(Operand::Reg(Register::raw(rt, false, false)))
                .with_operand(Operand::Imm(Immediate::new(crn as i64)))
                .with_operand(Operand::Imm(Immediate::new(crm as i64)))
                .with_operand(Operand::Imm(Immediate::new(op2 as i64))))
        }
    }

    fn decode_svc(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let imm24 = (raw & 0xFFFFFF) as i64;

        Ok(
            DecodedInsn::new(Mnemonic::SVC, ExecutionState::Aarch32, raw, 4)
                .with_operand(Operand::Imm(Immediate::new(imm24))),
        )
    }

    // =========================================================================
    // Media Instructions
    // =========================================================================

    fn decode_media(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let op1 = (raw >> 20) & 0x1F;
        let op2 = (raw >> 5) & 0x7;
        let rd = ((raw >> 12) & 0xF) as u8;
        let rn = ((raw >> 16) & 0xF) as u8;
        let rm = (raw & 0xF) as u8;
        let ra = ((raw >> 8) & 0xF) as u8; // Rs / Ra (bits 11:8)

        let mk = |m: Mnemonic, ops: &[u8]| {
            let mut insn = DecodedInsn::new(m, ExecutionState::Aarch32, raw, 4);
            for &o in ops {
                insn = insn.with_operand(Operand::Reg(Register::raw(o, false, false)));
            }
            Ok(insn)
        };

        // Parallel add/sub (signed & unsigned): bits[27:23] == 0b01100.
        if (raw >> 23) & 0x1F == 0b01100 {
            return mk(Mnemonic::A32_PARALLEL, &[rd, rn, rm]);
        }

        // Saturate (the sat_imm field spans bit 20, so match the fixed bits).
        let bits_27_21 = (raw >> 21) & 0x7F;
        let bits_5_4 = (raw >> 4) & 0x3;
        if bits_27_21 == 0b0110101 && bits_5_4 == 0b01 {
            return mk(Mnemonic::SSAT, &[rd]);
        }
        if bits_27_21 == 0b0110111 && bits_5_4 == 0b01 {
            return mk(Mnemonic::USAT, &[rd]);
        }
        let bits_7_4 = (raw >> 4) & 0xF;
        if (raw >> 20) & 0xFF == 0b01101010 && bits_7_4 == 0b0011 {
            return mk(Mnemonic::A32_SAT16, &[rd]); // SSAT16
        }
        if (raw >> 20) & 0xFF == 0b01101110 && bits_7_4 == 0b0011 {
            return mk(Mnemonic::A32_SAT16, &[rd]); // USAT16
        }

        match op1 {
            // PKH / SEL / SXTB16 / SXTAB16
            0b01000 => match op2 {
                0b000 | 0b010 => return mk(Mnemonic::A32_PKH, &[rd, rn, rm]),
                0b011 => return mk(Mnemonic::A32_EXTEND, &[rd, rn, rm]),
                0b101 => return mk(Mnemonic::A32_SEL, &[rd, rn, rm]),
                _ => {}
            },
            // SXTB / SXTAB (signed extend byte)
            0b01010 if op2 == 0b011 => return mk(Mnemonic::A32_EXTEND, &[rd, rn, rm]),
            // REV / REV16 / SXTH / SXTAH
            0b01011 => match op2 {
                0b001 => return mk(Mnemonic::REV, &[rd, rm]),
                0b101 => return mk(Mnemonic::REV16, &[rd, rm]),
                0b011 => return mk(Mnemonic::A32_EXTEND, &[rd, rn, rm]),
                _ => {}
            },
            // UXTB16 / UXTAB16
            0b01100 if op2 == 0b011 => return mk(Mnemonic::A32_EXTEND, &[rd, rn, rm]),
            // UXTB / UXTAB
            0b01110 if op2 == 0b011 => return mk(Mnemonic::A32_EXTEND, &[rd, rn, rm]),
            // RBIT / REVSH / UXTH / UXTAH
            0b01111 => match op2 {
                0b001 => return mk(Mnemonic::RBIT, &[rd, rm]),
                0b101 => return mk(Mnemonic::REVSH, &[rd, rm]),
                0b011 => return mk(Mnemonic::A32_EXTEND, &[rd, rn, rm]),
                _ => {}
            },
            // Signed multiply (dual / most-significant) + USAD8
            0b10000 => return mk(Mnemonic::A32_DUAL, &[rd, rn, rm, ra]),
            0b10100 => return mk(Mnemonic::A32_SMLALD, &[rd, rn, rm, ra]),
            0b10101 => return mk(Mnemonic::A32_SMMUL, &[rd, rn, rm, ra]),
            0b11000 if op2 == 0b000 => return mk(Mnemonic::A32_USAD, &[rd, rn, rm, ra]),
            _ => {}
        }

        // Bit-field: SBFX (1101x), BFI/BFC (1110x), UBFX (1111x).
        match op1 >> 1 {
            0b1101 => return mk(Mnemonic::SBFX, &[rd]),
            0b1110 => {
                if (raw & 0xF) == 0xF {
                    return mk(Mnemonic::BFC, &[rd]);
                } else {
                    return mk(Mnemonic::BFI, &[rd]);
                }
            }
            0b1111 => return mk(Mnemonic::UBFX, &[rd]),
            _ => {}
        }

        Ok(DecodedInsn::new(
            Mnemonic::UNKNOWN,
            ExecutionState::Aarch32,
            raw,
            4,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_bytes(bytes: &[u8; 4]) -> Result<DecodedInsn, DecodeError> {
        let raw = u32::from_le_bytes(*bytes);
        Aarch32Decoder::decode(raw)
    }

    #[test]
    fn test_nop() {
        // NOP: e320f000
        let insn = decode_bytes(&[0x00, 0xf0, 0x20, 0xe3]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::NOP);
    }

    #[test]
    fn test_mov_imm() {
        // MOV R0, #1: e3a00001
        let insn = decode_bytes(&[0x01, 0x00, 0xa0, 0xe3]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::MOV);
    }

    #[test]
    fn test_mov_reg() {
        // MOV R0, R1: e1a00001
        let insn = decode_bytes(&[0x01, 0x00, 0xa0, 0xe1]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::MOV);
    }

    #[test]
    fn test_add_reg() {
        // ADD R0, R1, R2: e0810002
        let insn = decode_bytes(&[0x02, 0x00, 0x81, 0xe0]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::ADD);
    }

    #[test]
    fn test_add_imm() {
        // ADD R0, R1, #0x10: e2810010
        let insn = decode_bytes(&[0x10, 0x00, 0x81, 0xe2]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::ADD);
    }

    #[test]
    fn test_sub_reg() {
        // SUB R0, R1, R2: e0410002
        let insn = decode_bytes(&[0x02, 0x00, 0x41, 0xe0]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::SUB);
    }

    #[test]
    fn test_cmp_reg() {
        // CMP R0, R1: e1500001
        let insn = decode_bytes(&[0x01, 0x00, 0x50, 0xe1]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::CMP);
    }

    #[test]
    fn test_and_reg() {
        // AND R0, R1, R2: e0010002
        let insn = decode_bytes(&[0x02, 0x00, 0x01, 0xe0]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::AND);
    }

    #[test]
    fn test_orr_reg() {
        // ORR R0, R1, R2: e1810002
        let insn = decode_bytes(&[0x02, 0x00, 0x81, 0xe1]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::ORR);
    }

    #[test]
    fn test_b() {
        // B #0x100: ea00003e
        let insn = decode_bytes(&[0x3e, 0x00, 0x00, 0xea]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::B);
    }

    #[test]
    fn test_bl() {
        // BL #0x100: eb00003e
        let insn = decode_bytes(&[0x3e, 0x00, 0x00, 0xeb]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::BL);
    }

    #[test]
    fn test_bx() {
        // BX LR: e12fff1e
        let insn = decode_bytes(&[0x1e, 0xff, 0x2f, 0xe1]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::BX);
    }

    #[test]
    fn test_ldr_imm() {
        // LDR R0, [R1]: e5910000
        let insn = decode_bytes(&[0x00, 0x00, 0x91, 0xe5]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::LDR);
    }

    #[test]
    fn test_str_imm() {
        // STR R0, [R1]: e5810000
        let insn = decode_bytes(&[0x00, 0x00, 0x81, 0xe5]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::STR);
    }

    #[test]
    fn test_ldrb() {
        // LDRB R0, [R1]: e5d10000
        let insn = decode_bytes(&[0x00, 0x00, 0xd1, 0xe5]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::LDRB);
    }

    #[test]
    fn test_push() {
        // PUSH {LR}: e52de004 (STMDB SP!, {LR})
        let insn = decode_bytes(&[0x00, 0x40, 0x2d, 0xe9]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::PUSH);
    }

    #[test]
    fn test_pop() {
        // POP {PC}: e8bd8000 (LDMIA SP!, {PC})
        let insn = decode_bytes(&[0x00, 0x80, 0xbd, 0xe8]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::POP);
    }

    #[test]
    fn test_mul() {
        // MUL R0, R1, R2: e0000291
        let insn = decode_bytes(&[0x91, 0x02, 0x00, 0xe0]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::MUL);
    }

    #[test]
    fn test_svc() {
        // SVC #0: ef000000
        let insn = decode_bytes(&[0x00, 0x00, 0x00, 0xef]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::SVC);
    }

    #[test]
    fn test_conditional() {
        // MOVEQ R0, #1: 03a00001
        let insn = decode_bytes(&[0x01, 0x00, 0xa0, 0x03]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::MOV);
        assert_eq!(insn.cond, Some(Condition::EQ));
    }

    #[test]
    fn test_shifted_reg() {
        // ADD R0, R1, R2, LSL #4: e0810102
        let insn = decode_bytes(&[0x02, 0x01, 0x81, 0xe0]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::ADD);
        assert_eq!(insn.operands.len(), 3);
    }

    #[test]
    fn test_mvn() {
        // MVN R0, R1: e1e00001
        let insn = decode_bytes(&[0x01, 0x00, 0xe0, 0xe1]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::MVN);
    }

    #[test]
    fn test_clz() {
        // CLZ R0, R1: e16f0f11
        let insn = decode_bytes(&[0x11, 0x0f, 0x6f, 0xe1]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::CLZ);
    }
}

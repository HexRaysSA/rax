//! Thumb (T16) and Thumb-2 (T32) instruction decoder.
//!
//! This module decodes Thumb instructions, which are either 16 or 32 bits wide.
//! 32-bit Thumb-2 instructions are encoded as two halfwords.

use super::{Condition, DecodeError, DecodedInsn, Mnemonic, ShiftType, operand::*};
use crate::isa::arm::ExecutionState;

mod t32;

/// Thumb instruction decoder.
pub struct ThumbDecoder;

impl ThumbDecoder {
    /// Check if a 16-bit halfword indicates a 32-bit instruction.
    ///
    /// 32-bit Thumb instructions start with 0b11101, 0b11110, or 0b11111.
    pub fn is_32bit_instruction(hw1: u16) -> bool {
        let op = hw1 >> 11;
        op == 0b11101 || op == 0b11110 || op == 0b11111
    }

    /// Decode a 16-bit Thumb instruction.
    pub fn decode_16bit(raw: u16) -> Result<DecodedInsn, DecodeError> {
        let op = raw >> 10;

        match op {
            // Shift (immediate), add, subtract, move, and compare
            0b000000..=0b001111 => Self::decode_shift_add_sub_mov_cmp(raw),
            // Data processing
            0b010000 => Self::decode_data_processing(raw),
            // Special data instructions and branch and exchange
            0b010001 => Self::decode_special_data_branch(raw),
            // Load from literal pool (PC-relative)
            0b01001_0 | 0b01001_1 => Self::decode_ldr_literal(raw),
            // Load/store single data item
            0b0101_00..=0b0101_11
            | 0b0110_00..=0b0110_11
            | 0b0111_00..=0b0111_11
            | 0b1000_00..=0b1000_11
            | 0b1001_00..=0b1001_11 => Self::decode_load_store(raw),
            // Generate PC-relative address (ADR)
            0b10100_0 | 0b10100_1 => Self::decode_adr(raw),
            // Generate SP-relative address (ADD SP)
            0b10101_0 | 0b10101_1 => Self::decode_add_sp(raw),
            // Miscellaneous 16-bit instructions
            0b1011_00..=0b1011_11 => Self::decode_miscellaneous(raw),
            // Store/load multiple
            0b11000_0 | 0b11000_1 => Self::decode_stm(raw),
            0b11001_0 | 0b11001_1 => Self::decode_ldm(raw),
            // Conditional branch and supervisor call
            0b1101_00..=0b1101_11 => Self::decode_cond_branch_svc(raw),
            // Unconditional branch
            0b11100_0 | 0b11100_1 => Self::decode_uncond_branch(raw),
            _ => Ok(DecodedInsn::new(
                Mnemonic::UNKNOWN,
                ExecutionState::Thumb,
                raw as u32,
                2,
            )),
        }
    }

    /// Decode a 32-bit Thumb-2 instruction.
    ///
    /// The raw value has hw1 in the high 16 bits and hw2 in the low 16 bits.
    pub fn decode_32bit(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let hw1 = (raw >> 16) as u16;
        let hw2 = raw as u16;

        let op1 = (hw1 >> 11) & 0x3;
        let op2 = (hw1 >> 4) & 0x7F;
        let op = (hw2 >> 15) & 1;

        match op1 {
            0b01 => {
                // Load/store multiple, load/store dual, table branch
                if op2 & 0x64 == 0x00 {
                    Self::decode_32bit_load_store_multiple(raw)
                } else if op2 & 0x64 == 0x04 {
                    Self::decode_32bit_load_store_dual(raw)
                } else {
                    Self::decode_32bit_data_processing(raw)
                }
            }
            0b10 => {
                if op == 0 {
                    // bit25 (hw1 bit9) selects modified-immediate vs plain-binary.
                    if (hw1 >> 9) & 1 == 0 {
                        Self::decode_32bit_dp_modified_imm(raw)
                    } else {
                        Self::decode_32bit_dp_plain_imm(raw)
                    }
                } else {
                    // Branches and miscellaneous control
                    Self::decode_32bit_branch_misc(raw)
                }
            }
            0b11 => {
                if op2 & 0x70 == 0x20 {
                    // Data processing (register)
                    Self::decode_32bit_dp_register(raw)
                } else if op2 & 0x78 == 0x30 {
                    // Multiply, multiply accumulate, and absolute difference
                    Self::decode_32bit_multiply(raw)
                } else if op2 & 0x78 == 0x38 {
                    // Long multiply, long multiply accumulate, divide
                    Self::decode_32bit_long_multiply_divide(raw)
                } else if op2 & 0x67 == 0x01 {
                    // Load byte, memory hints
                    Self::decode_32bit_load_byte(raw)
                } else if op2 & 0x67 == 0x03 {
                    // Load halfword
                    Self::decode_32bit_load_halfword(raw)
                } else if op2 & 0x67 == 0x05 {
                    // Load word
                    Self::decode_32bit_load_word(raw)
                } else if op2 & 0x71 == 0x00 {
                    // Store single data item
                    Self::decode_32bit_store(raw)
                } else {
                    Ok(DecodedInsn::new(
                        Mnemonic::UNKNOWN,
                        ExecutionState::Thumb2,
                        raw,
                        4,
                    ))
                }
            }
            _ => Ok(DecodedInsn::new(
                Mnemonic::UNKNOWN,
                ExecutionState::Thumb2,
                raw,
                4,
            )),
        }
    }

    // =========================================================================
    // 16-bit Thumb Decoders
    // =========================================================================

    fn decode_shift_add_sub_mov_cmp(raw: u16) -> Result<DecodedInsn, DecodeError> {
        // Thumb 16-bit encoding for shift/add/sub/mov/cmp:
        // Bits [15:14] = 00
        // Bits [13:11] determine the major category
        let op_major = (raw >> 11) & 0x7;

        match op_major {
            // 000: LSL (immediate)
            0b000 => {
                let imm5 = ((raw >> 6) & 0x1F) as u8;
                let rm = ((raw >> 3) & 0x7) as u8;
                let rd = (raw & 0x7) as u8;

                // LSL with imm5=0 is MOV alias
                let mnemonic = if imm5 == 0 {
                    Mnemonic::MOVS
                } else {
                    Mnemonic::LSLS
                };
                let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Thumb, raw as u32, 2);
                insn.sets_flags = true;
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rd)));
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rm)));
                if imm5 != 0 {
                    insn = insn.with_operand(Operand::Imm(Immediate::new(imm5 as i64)));
                }
                Ok(insn)
            }
            // 001: LSR (immediate)
            0b001 => {
                let imm5 = ((raw >> 6) & 0x1F) as u8;
                let rm = ((raw >> 3) & 0x7) as u8;
                let rd = (raw & 0x7) as u8;

                let shift_amt = if imm5 == 0 { 32 } else { imm5 as i64 };

                let mut insn =
                    DecodedInsn::new(Mnemonic::LSRS, ExecutionState::Thumb, raw as u32, 2);
                insn.sets_flags = true;
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rd)));
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rm)));
                insn = insn.with_operand(Operand::Imm(Immediate::new(shift_amt)));
                Ok(insn)
            }
            // 010: ASR (immediate)
            0b010 => {
                let imm5 = ((raw >> 6) & 0x1F) as u8;
                let rm = ((raw >> 3) & 0x7) as u8;
                let rd = (raw & 0x7) as u8;

                let shift_amt = if imm5 == 0 { 32 } else { imm5 as i64 };

                let mut insn =
                    DecodedInsn::new(Mnemonic::ASRS, ExecutionState::Thumb, raw as u32, 2);
                insn.sets_flags = true;
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rd)));
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rm)));
                insn = insn.with_operand(Operand::Imm(Immediate::new(shift_amt)));
                Ok(insn)
            }
            // 011: ADD/SUB (register or 3-bit immediate)
            0b011 => {
                let i = (raw >> 10) & 1; // 0 = register, 1 = immediate
                let op_bit = (raw >> 9) & 1; // 0 = ADD, 1 = SUB
                let rn = ((raw >> 3) & 0x7) as u8;
                let rd = (raw & 0x7) as u8;

                let mnemonic = if op_bit == 0 {
                    Mnemonic::ADDS
                } else {
                    Mnemonic::SUBS
                };

                let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Thumb, raw as u32, 2);
                insn.sets_flags = true;
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rd)));
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rn)));

                if i == 0 {
                    // Register variant
                    let rm = ((raw >> 6) & 0x7) as u8;
                    insn = insn.with_operand(Operand::Reg(Self::low_reg(rm)));
                } else {
                    // 3-bit immediate variant
                    let imm3 = ((raw >> 6) & 0x7) as i64;
                    insn = insn.with_operand(Operand::Imm(Immediate::new(imm3)));
                }
                Ok(insn)
            }
            // 100: MOV (immediate)
            0b100 => {
                let rd = ((raw >> 8) & 0x7) as u8;
                let imm8 = (raw & 0xFF) as i64;

                let mut insn =
                    DecodedInsn::new(Mnemonic::MOVS, ExecutionState::Thumb, raw as u32, 2);
                insn.sets_flags = true;
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rd)));
                insn = insn.with_operand(Operand::Imm(Immediate::new(imm8)));
                Ok(insn)
            }
            // 101: CMP (immediate)
            0b101 => {
                let rn = ((raw >> 8) & 0x7) as u8;
                let imm8 = (raw & 0xFF) as i64;

                let mut insn =
                    DecodedInsn::new(Mnemonic::CMP, ExecutionState::Thumb, raw as u32, 2);
                insn.sets_flags = true;
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rn)));
                insn = insn.with_operand(Operand::Imm(Immediate::new(imm8)));
                Ok(insn)
            }
            // 110: ADD (8-bit immediate)
            0b110 => {
                let rdn = ((raw >> 8) & 0x7) as u8;
                let imm8 = (raw & 0xFF) as i64;

                let mut insn =
                    DecodedInsn::new(Mnemonic::ADDS, ExecutionState::Thumb, raw as u32, 2);
                insn.sets_flags = true;
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rdn)));
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rdn)));
                insn = insn.with_operand(Operand::Imm(Immediate::new(imm8)));
                Ok(insn)
            }
            // 111: SUB (8-bit immediate)
            0b111 => {
                let rdn = ((raw >> 8) & 0x7) as u8;
                let imm8 = (raw & 0xFF) as i64;

                let mut insn =
                    DecodedInsn::new(Mnemonic::SUBS, ExecutionState::Thumb, raw as u32, 2);
                insn.sets_flags = true;
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rdn)));
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rdn)));
                insn = insn.with_operand(Operand::Imm(Immediate::new(imm8)));
                Ok(insn)
            }
            _ => Ok(DecodedInsn::new(
                Mnemonic::UNKNOWN,
                ExecutionState::Thumb,
                raw as u32,
                2,
            )),
        }
    }

    fn decode_data_processing(raw: u16) -> Result<DecodedInsn, DecodeError> {
        let op = (raw >> 6) & 0xF;
        let rm = ((raw >> 3) & 0x7) as u8;
        let rdn = (raw & 0x7) as u8;

        let (mnemonic, uses_rd_as_rn) = match op {
            0b0000 => (Mnemonic::ANDS, true),
            0b0001 => (Mnemonic::EORS, true),
            0b0010 => (Mnemonic::LSLS, true),
            0b0011 => (Mnemonic::LSRS, true),
            0b0100 => (Mnemonic::ASRS, true),
            0b0101 => (Mnemonic::ADCS, true),
            0b0110 => (Mnemonic::SBCS, true),
            0b0111 => (Mnemonic::RORS, true),
            0b1000 => (Mnemonic::TST, false),  // Rd not written
            0b1001 => (Mnemonic::NEGS, false), // RSB Rd, Rm, #0
            0b1010 => (Mnemonic::CMP, false),
            0b1011 => (Mnemonic::CMN, false),
            0b1100 => (Mnemonic::ORRS, true),
            0b1101 => (Mnemonic::MULS, true),
            0b1110 => (Mnemonic::BICS, true),
            0b1111 => (Mnemonic::MVNS, false),
            _ => unreachable!(),
        };

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Thumb, raw as u32, 2);
        insn.sets_flags = true;

        match op {
            // TST, CMP, CMN - no destination
            0b1000 | 0b1010 | 0b1011 => {
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rdn)));
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rm)));
            }
            // NEG (RSB Rd, Rm, #0)
            0b1001 => {
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rdn)));
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rm)));
            }
            // MVN
            0b1111 => {
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rdn)));
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rm)));
            }
            // MUL
            0b1101 => {
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rdn)));
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rm)));
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rdn)));
            }
            // Other operations: Rd, Rd, Rm
            _ => {
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rdn)));
                if uses_rd_as_rn {
                    insn = insn.with_operand(Operand::Reg(Self::low_reg(rdn)));
                }
                insn = insn.with_operand(Operand::Reg(Self::low_reg(rm)));
            }
        }

        Ok(insn)
    }

    fn decode_special_data_branch(raw: u16) -> Result<DecodedInsn, DecodeError> {
        let op = (raw >> 6) & 0xF;

        match op {
            // ADD (register) - high registers
            0b0000..=0b0011 => {
                let dn = (raw >> 7) & 1;
                let rm = ((raw >> 3) & 0xF) as u8;
                let rdn = (((dn << 3) as u8) | (raw & 0x7) as u8);

                Ok(
                    DecodedInsn::new(Mnemonic::ADD, ExecutionState::Thumb, raw as u32, 2)
                        .with_operand(Operand::Reg(Self::any_reg(rdn)))
                        .with_operand(Operand::Reg(Self::any_reg(rdn)))
                        .with_operand(Operand::Reg(Self::any_reg(rm))),
                )
            }
            // CMP (register) - high registers
            0b0101 | 0b0110 | 0b0111 => {
                let n = (raw >> 7) & 1;
                let rm = ((raw >> 3) & 0xF) as u8;
                let rn = (((n << 3) as u8) | (raw & 0x7) as u8);

                let mut insn =
                    DecodedInsn::new(Mnemonic::CMP, ExecutionState::Thumb, raw as u32, 2);
                insn.sets_flags = true;
                insn = insn.with_operand(Operand::Reg(Self::any_reg(rn)));
                insn = insn.with_operand(Operand::Reg(Self::any_reg(rm)));
                Ok(insn)
            }
            // MOV (register) - high registers
            0b1000..=0b1011 => {
                let d = (raw >> 7) & 1;
                let rm = ((raw >> 3) & 0xF) as u8;
                let rd = (((d << 3) as u8) | (raw & 0x7) as u8);

                Ok(
                    DecodedInsn::new(Mnemonic::MOV, ExecutionState::Thumb, raw as u32, 2)
                        .with_operand(Operand::Reg(Self::any_reg(rd)))
                        .with_operand(Operand::Reg(Self::any_reg(rm))),
                )
            }
            // BX
            0b1100 | 0b1101 => {
                let rm = ((raw >> 3) & 0xF) as u8;

                Ok(
                    DecodedInsn::new(Mnemonic::BX, ExecutionState::Thumb, raw as u32, 2)
                        .with_operand(Operand::Reg(Self::any_reg(rm))),
                )
            }
            // BLX (register)
            0b1110 | 0b1111 => {
                let rm = ((raw >> 3) & 0xF) as u8;

                Ok(
                    DecodedInsn::new(Mnemonic::BLX, ExecutionState::Thumb, raw as u32, 2)
                        .with_operand(Operand::Reg(Self::any_reg(rm))),
                )
            }
            _ => Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Thumb,
                raw as u32,
                2,
            )),
        }
    }

    fn decode_ldr_literal(raw: u16) -> Result<DecodedInsn, DecodeError> {
        let rt = ((raw >> 8) & 0x7) as u8;
        let imm8 = (raw & 0xFF) as i64;
        let offset = imm8 << 2;

        // LDR Rt, [PC, #offset]
        Ok(
            DecodedInsn::new(Mnemonic::LDR, ExecutionState::Thumb, raw as u32, 2)
                .with_operand(Operand::Reg(Self::low_reg(rt)))
                .with_operand(Operand::Label(offset)),
        )
    }

    fn decode_load_store(raw: u16) -> Result<DecodedInsn, DecodeError> {
        let op_a = (raw >> 12) & 0xF;
        let op_b = (raw >> 9) & 0x7;

        match (op_a, op_b) {
            // STR (register)
            (0b0101, 0b000) => Self::decode_ls_reg(raw, Mnemonic::STR),
            // STRH (register)
            (0b0101, 0b001) => Self::decode_ls_reg(raw, Mnemonic::STRH),
            // STRB (register)
            (0b0101, 0b010) => Self::decode_ls_reg(raw, Mnemonic::STRB),
            // LDRSB (register)
            (0b0101, 0b011) => Self::decode_ls_reg(raw, Mnemonic::LDRSB),
            // LDR (register)
            (0b0101, 0b100) => Self::decode_ls_reg(raw, Mnemonic::LDR),
            // LDRH (register)
            (0b0101, 0b101) => Self::decode_ls_reg(raw, Mnemonic::LDRH),
            // LDRB (register)
            (0b0101, 0b110) => Self::decode_ls_reg(raw, Mnemonic::LDRB),
            // LDRSH (register)
            (0b0101, 0b111) => Self::decode_ls_reg(raw, Mnemonic::LDRSH),
            // STR (immediate, T1)
            (0b0110, _) if op_b & 0b100 == 0 => Self::decode_ls_imm_word(raw, false),
            // LDR (immediate, T1)
            (0b0110, _) if op_b & 0b100 != 0 => Self::decode_ls_imm_word(raw, true),
            // STRB (immediate)
            (0b0111, _) if op_b & 0b100 == 0 => Self::decode_ls_imm_byte(raw, false),
            // LDRB (immediate)
            (0b0111, _) if op_b & 0b100 != 0 => Self::decode_ls_imm_byte(raw, true),
            // STRH (immediate)
            (0b1000, _) if op_b & 0b100 == 0 => Self::decode_ls_imm_halfword(raw, false),
            // LDRH (immediate)
            (0b1000, _) if op_b & 0b100 != 0 => Self::decode_ls_imm_halfword(raw, true),
            // STR (immediate, T2) - SP relative
            (0b1001, _) if op_b & 0b100 == 0 => Self::decode_ls_sp_relative(raw, false),
            // LDR (immediate, T2) - SP relative
            (0b1001, _) if op_b & 0b100 != 0 => Self::decode_ls_sp_relative(raw, true),
            _ => Ok(DecodedInsn::new(
                Mnemonic::UNKNOWN,
                ExecutionState::Thumb,
                raw as u32,
                2,
            )),
        }
    }

    fn decode_ls_reg(raw: u16, mnemonic: Mnemonic) -> Result<DecodedInsn, DecodeError> {
        let rm = ((raw >> 6) & 0x7) as u8;
        let rn = ((raw >> 3) & 0x7) as u8;
        let rt = (raw & 0x7) as u8;

        let mem = MemOperand {
            base: Self::low_reg(rn),
            offset: MemOffset::Reg(Self::low_reg(rm)),
            mode: AddressingMode::Offset,
        };

        Ok(
            DecodedInsn::new(mnemonic, ExecutionState::Thumb, raw as u32, 2)
                .with_operand(Operand::Reg(Self::low_reg(rt)))
                .with_operand(Operand::Mem(mem)),
        )
    }

    fn decode_ls_imm_word(raw: u16, is_load: bool) -> Result<DecodedInsn, DecodeError> {
        let imm5 = ((raw >> 6) & 0x1F) as i64;
        let rn = ((raw >> 3) & 0x7) as u8;
        let rt = (raw & 0x7) as u8;
        let offset = imm5 << 2;

        let mnemonic = if is_load {
            Mnemonic::LDR
        } else {
            Mnemonic::STR
        };

        Ok(
            DecodedInsn::new(mnemonic, ExecutionState::Thumb, raw as u32, 2)
                .with_operand(Operand::Reg(Self::low_reg(rt)))
                .with_operand(Operand::Mem(MemOperand::imm_offset(
                    Self::low_reg(rn),
                    offset,
                ))),
        )
    }

    fn decode_ls_imm_byte(raw: u16, is_load: bool) -> Result<DecodedInsn, DecodeError> {
        let imm5 = ((raw >> 6) & 0x1F) as i64;
        let rn = ((raw >> 3) & 0x7) as u8;
        let rt = (raw & 0x7) as u8;

        let mnemonic = if is_load {
            Mnemonic::LDRB
        } else {
            Mnemonic::STRB
        };

        Ok(
            DecodedInsn::new(mnemonic, ExecutionState::Thumb, raw as u32, 2)
                .with_operand(Operand::Reg(Self::low_reg(rt)))
                .with_operand(Operand::Mem(MemOperand::imm_offset(
                    Self::low_reg(rn),
                    imm5,
                ))),
        )
    }

    fn decode_ls_imm_halfword(raw: u16, is_load: bool) -> Result<DecodedInsn, DecodeError> {
        let imm5 = ((raw >> 6) & 0x1F) as i64;
        let rn = ((raw >> 3) & 0x7) as u8;
        let rt = (raw & 0x7) as u8;
        let offset = imm5 << 1;

        let mnemonic = if is_load {
            Mnemonic::LDRH
        } else {
            Mnemonic::STRH
        };

        Ok(
            DecodedInsn::new(mnemonic, ExecutionState::Thumb, raw as u32, 2)
                .with_operand(Operand::Reg(Self::low_reg(rt)))
                .with_operand(Operand::Mem(MemOperand::imm_offset(
                    Self::low_reg(rn),
                    offset,
                ))),
        )
    }

    fn decode_ls_sp_relative(raw: u16, is_load: bool) -> Result<DecodedInsn, DecodeError> {
        let rt = ((raw >> 8) & 0x7) as u8;
        let imm8 = (raw & 0xFF) as i64;
        let offset = imm8 << 2;

        let mnemonic = if is_load {
            Mnemonic::LDR
        } else {
            Mnemonic::STR
        };

        // SP is r13
        Ok(
            DecodedInsn::new(mnemonic, ExecutionState::Thumb, raw as u32, 2)
                .with_operand(Operand::Reg(Self::low_reg(rt)))
                .with_operand(Operand::Mem(MemOperand::imm_offset(
                    Register::sp32(),
                    offset,
                ))),
        )
    }

    fn decode_adr(raw: u16) -> Result<DecodedInsn, DecodeError> {
        let rd = ((raw >> 8) & 0x7) as u8;
        let imm8 = (raw & 0xFF) as i64;
        let offset = imm8 << 2;

        // ADR Rd, label (actually ADD Rd, PC, #offset)
        Ok(
            DecodedInsn::new(Mnemonic::ADD, ExecutionState::Thumb, raw as u32, 2)
                .with_operand(Operand::Reg(Self::low_reg(rd)))
                .with_operand(Operand::Label(offset)),
        )
    }

    fn decode_add_sp(raw: u16) -> Result<DecodedInsn, DecodeError> {
        let rd = ((raw >> 8) & 0x7) as u8;
        let imm8 = (raw & 0xFF) as i64;
        let offset = imm8 << 2;

        // ADD Rd, SP, #imm
        Ok(
            DecodedInsn::new(Mnemonic::ADD, ExecutionState::Thumb, raw as u32, 2)
                .with_operand(Operand::Reg(Self::low_reg(rd)))
                .with_operand(Operand::Reg(Register::sp32()))
                .with_operand(Operand::Imm(Immediate::new(offset))),
        )
    }

    fn decode_miscellaneous(raw: u16) -> Result<DecodedInsn, DecodeError> {
        // Miscellaneous 16-bit: bits [15:12] = 1011, bits [11:8] = opcode
        let op = (raw >> 8) & 0xF;

        match op {
            // 0000: ADD/SUB SP
            0b0000 => {
                let s = (raw >> 7) & 1;
                let imm7 = (raw & 0x7F) as i64;
                let offset = imm7 << 2;

                let mnemonic = if s == 0 { Mnemonic::ADD } else { Mnemonic::SUB };
                Ok(
                    DecodedInsn::new(mnemonic, ExecutionState::Thumb, raw as u32, 2)
                        .with_operand(Operand::Reg(Register::sp32()))
                        .with_operand(Operand::Reg(Register::sp32()))
                        .with_operand(Operand::Imm(Immediate::new(offset))),
                )
            }
            // 0001: CBZ (forward reference only)
            0b0001 | 0b0011 => {
                let i = (raw >> 9) & 1;
                let imm5 = (raw >> 3) & 0x1F;
                let rn = (raw & 0x7) as u8;
                let imm = ((i << 6) | (imm5 << 1)) as i64;

                Ok(
                    DecodedInsn::new(Mnemonic::CBZ, ExecutionState::Thumb, raw as u32, 2)
                        .with_operand(Operand::Reg(Self::low_reg(rn)))
                        .with_operand(Operand::Label(imm)),
                )
            }
            // 0010: SXTH, SXTB, UXTH, UXTB
            0b0010 => {
                let rm = ((raw >> 3) & 0x7) as u8;
                let rd = (raw & 0x7) as u8;
                let op2 = (raw >> 6) & 0x3;

                let mnemonic = match op2 {
                    0b00 => Mnemonic::SXTH,
                    0b01 => Mnemonic::SXTB,
                    0b10 => Mnemonic::UXTH,
                    0b11 => Mnemonic::UXTB,
                    _ => unreachable!(),
                };

                Ok(
                    DecodedInsn::new(mnemonic, ExecutionState::Thumb, raw as u32, 2)
                        .with_operand(Operand::Reg(Self::low_reg(rd)))
                        .with_operand(Operand::Reg(Self::low_reg(rm))),
                )
            }
            // 0100, 0101: PUSH
            0b0100 | 0b0101 => {
                let m = (raw >> 8) & 1;
                let reg_list = ((raw & 0xFF) | ((m as u16) << 14)) as u16;

                Ok(
                    DecodedInsn::new(Mnemonic::PUSH, ExecutionState::Thumb, raw as u32, 2)
                        .with_operand(Operand::RegList(RegisterList::from_mask(reg_list))),
                )
            }
            // 1001: CBNZ
            0b1001 | 0b1011 => {
                let i = (raw >> 9) & 1;
                let imm5 = (raw >> 3) & 0x1F;
                let rn = (raw & 0x7) as u8;
                let imm = ((i << 6) | (imm5 << 1)) as i64;

                Ok(
                    DecodedInsn::new(Mnemonic::CBNZ, ExecutionState::Thumb, raw as u32, 2)
                        .with_operand(Operand::Reg(Self::low_reg(rn)))
                        .with_operand(Operand::Label(imm)),
                )
            }
            // 1010: REV, REV16, REVSH
            0b1010 => {
                let rm = ((raw >> 3) & 0x7) as u8;
                let rd = (raw & 0x7) as u8;
                let op2 = (raw >> 6) & 0x3;

                let mnemonic = match op2 {
                    0b00 => Mnemonic::REV,
                    0b01 => Mnemonic::REV16,
                    0b11 => Mnemonic::REVSH,
                    _ => Mnemonic::UNDEFINED,
                };

                Ok(
                    DecodedInsn::new(mnemonic, ExecutionState::Thumb, raw as u32, 2)
                        .with_operand(Operand::Reg(Self::low_reg(rd)))
                        .with_operand(Operand::Reg(Self::low_reg(rm))),
                )
            }
            // 1100, 1101: POP
            0b1100 | 0b1101 => {
                let p = (raw >> 8) & 1;
                let reg_list = ((raw & 0xFF) | ((p as u16) << 15)) as u16;

                Ok(
                    DecodedInsn::new(Mnemonic::POP, ExecutionState::Thumb, raw as u32, 2)
                        .with_operand(Operand::RegList(RegisterList::from_mask(reg_list))),
                )
            }
            // 1110: BKPT
            0b1110 => {
                let imm8 = (raw & 0xFF) as i64;

                Ok(
                    DecodedInsn::new(Mnemonic::BKPT, ExecutionState::Thumb, raw as u32, 2)
                        .with_operand(Operand::Imm(Immediate::new(imm8))),
                )
            }
            // 1111: If-Then/Hints
            0b1111 => {
                let op_a = (raw >> 4) & 0xF;
                let op_b = raw & 0xF;

                if op_b != 0 {
                    // IT instruction
                    return Ok(DecodedInsn::new(
                        Mnemonic::IT,
                        ExecutionState::Thumb,
                        raw as u32,
                        2,
                    ));
                }

                let mnemonic = match op_b {
                    0b0000 => Mnemonic::NOP,
                    0b0001 => Mnemonic::YIELD,
                    0b0010 => Mnemonic::WFE,
                    0b0011 => Mnemonic::WFI,
                    0b0100 => Mnemonic::SEV,
                    _ => Mnemonic::HINT,
                };

                Ok(DecodedInsn::new(
                    mnemonic,
                    ExecutionState::Thumb,
                    raw as u32,
                    2,
                ))
            }
            _ => Ok(DecodedInsn::new(
                Mnemonic::UNKNOWN,
                ExecutionState::Thumb,
                raw as u32,
                2,
            )),
        }
    }

    fn decode_stm(raw: u16) -> Result<DecodedInsn, DecodeError> {
        let rn = ((raw >> 8) & 0x7) as u8;
        let reg_list = (raw & 0xFF) as u16;

        Ok(
            DecodedInsn::new(Mnemonic::STMIA, ExecutionState::Thumb, raw as u32, 2)
                .with_operand(Operand::Reg(Self::low_reg(rn)))
                .with_operand(Operand::RegList(RegisterList::from_mask(reg_list))),
        )
    }

    fn decode_ldm(raw: u16) -> Result<DecodedInsn, DecodeError> {
        let rn = ((raw >> 8) & 0x7) as u8;
        let reg_list = (raw & 0xFF) as u16;

        Ok(
            DecodedInsn::new(Mnemonic::LDMIA, ExecutionState::Thumb, raw as u32, 2)
                .with_operand(Operand::Reg(Self::low_reg(rn)))
                .with_operand(Operand::RegList(RegisterList::from_mask(reg_list))),
        )
    }

    fn decode_cond_branch_svc(raw: u16) -> Result<DecodedInsn, DecodeError> {
        let op = (raw >> 8) & 0xF;

        if op == 0b1110 {
            // UDF
            let imm8 = (raw & 0xFF) as i64;
            return Ok(
                DecodedInsn::new(Mnemonic::UDF, ExecutionState::Thumb, raw as u32, 2)
                    .with_operand(Operand::Imm(Immediate::new(imm8))),
            );
        }

        if op == 0b1111 {
            // SVC
            let imm8 = (raw & 0xFF) as i64;
            return Ok(
                DecodedInsn::new(Mnemonic::SVC, ExecutionState::Thumb, raw as u32, 2)
                    .with_operand(Operand::Imm(Immediate::new(imm8))),
            );
        }

        // Conditional branch
        let cond = Condition::from_bits(op as u8);
        let imm8 = (raw & 0xFF) as i64;

        // Sign extend and shift
        let offset = if imm8 & (1 << 7) != 0 {
            (imm8 | !0xFF) << 1
        } else {
            imm8 << 1
        };

        Ok(
            DecodedInsn::new(Mnemonic::BCC, ExecutionState::Thumb, raw as u32, 2)
                .with_cond(cond)
                .with_operand(Operand::Label(offset)),
        )
    }

    fn decode_uncond_branch(raw: u16) -> Result<DecodedInsn, DecodeError> {
        let imm11 = (raw & 0x7FF) as i64;

        // Sign extend and shift
        let offset = if imm11 & (1 << 10) != 0 {
            (imm11 | !0x7FF) << 1
        } else {
            imm11 << 1
        };

        Ok(
            DecodedInsn::new(Mnemonic::B, ExecutionState::Thumb, raw as u32, 2)
                .with_operand(Operand::Label(offset)),
        )
    }

    // =========================================================================
    // Helper functions
    // =========================================================================

    /// Create a low register (r0-r7).
    fn low_reg(num: u8) -> Register {
        Register::raw(num & 0x7, false, false)
    }

    /// Create any register (r0-r15).
    fn any_reg(num: u8) -> Register {
        if num == 13 {
            Register::sp32()
        } else {
            Register::raw(num & 0xF, false, false)
        }
    }
}

// Placeholder for extension sign-extend mnemonics
#[allow(non_camel_case_types)]
impl Mnemonic {
    // Extension aliases not in the main enum
}

// Add these aliases to Mnemonic
const _SXTH: Mnemonic = Mnemonic::SBFM;
const _SXTB: Mnemonic = Mnemonic::SBFM;
const _UXTH: Mnemonic = Mnemonic::UBFM;
const _UXTB: Mnemonic = Mnemonic::UBFM;
const _REVSH: Mnemonic = Mnemonic::REV16;

#[cfg(test)]
mod tests;

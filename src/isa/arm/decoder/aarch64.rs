//! AArch64 (A64) instruction decoder.
//!
//! This module decodes 64-bit ARM instructions (AArch64/A64).
//! All A64 instructions are 32 bits wide.

use super::{Condition, DecodeError, DecodedInsn, ExtendType, Mnemonic, ShiftType, operand::*};
use crate::isa::arm::ExecutionState;

/// AArch64 instruction decoder.
pub struct Aarch64Decoder;

mod pauth;

impl Aarch64Decoder {
    /// Decode a 32-bit AArch64 instruction.
    pub fn decode(raw: u32) -> Result<DecodedInsn, DecodeError> {
        // Extract top-level opcode bits for classification
        // A64 encoding uses bits [28:25] as the main encoding group
        let op0 = (raw >> 25) & 0xF;

        match op0 {
            // 0b0000: Reserved / unallocated
            0b0000 => Self::decode_reserved(raw),

            // 0b0001: Unallocated
            0b0001 => Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            )),

            // 0b0010: SVE encodings
            0b0010 => Self::decode_sve(raw),

            // 0b0011: Unallocated
            0b0011 => Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            )),

            // 0b100x: Data processing - immediate
            0b1000 | 0b1001 => Self::decode_dp_imm(raw),

            // 0b101x: Branch, exception generation, and system
            0b1010 | 0b1011 => Self::decode_branch_sys(raw),

            // 0b1100, 0b1110: Loads and stores
            0b0100 | 0b0110 | 0b1100 | 0b1110 => Self::decode_load_store(raw),

            // 0b0101, 0b1101: Data processing - register
            0b0101 | 0b1101 => Self::decode_dp_reg(raw),

            // 0b0111, 0b1111: Data processing - SIMD and FP
            0b0111 | 0b1111 => Self::decode_simd_fp(raw),

            _ => Ok(DecodedInsn::new(
                Mnemonic::UNKNOWN,
                ExecutionState::Aarch64,
                raw,
                4,
            )),
        }
    }

    // =========================================================================
    // Reserved / Unallocated
    // =========================================================================

    fn decode_reserved(raw: u32) -> Result<DecodedInsn, DecodeError> {
        // UDF is encoded with all zeros in specific fields
        if raw == 0 {
            return Ok(
                DecodedInsn::new(Mnemonic::UDF, ExecutionState::Aarch64, raw, 4)
                    .with_operand(Operand::Imm(Immediate::new(0))),
            );
        }
        Ok(DecodedInsn::new(
            Mnemonic::UNDEFINED,
            ExecutionState::Aarch64,
            raw,
            4,
        ))
    }

    // =========================================================================
    // Data Processing - Immediate
    // =========================================================================

    fn decode_dp_imm(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let op0 = (raw >> 23) & 0x7;

        match op0 {
            // PC-rel addressing
            0b000 | 0b001 => Self::decode_pc_rel(raw),
            // Add/sub immediate
            0b010 => Self::decode_add_sub_imm(raw),
            // Add/sub immediate with tags
            0b011 => Self::decode_add_sub_imm_tags(raw),
            // Logical immediate
            0b100 => Self::decode_logical_imm(raw),
            // Move wide immediate
            0b101 => Self::decode_move_wide_imm(raw),
            // Bitfield
            0b110 => Self::decode_bitfield(raw),
            // Extract
            0b111 => Self::decode_extract(raw),
            _ => Ok(DecodedInsn::new(
                Mnemonic::UNKNOWN,
                ExecutionState::Aarch64,
                raw,
                4,
            )),
        }
    }

    fn decode_pc_rel(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let op = (raw >> 31) & 1;
        let immlo = (raw >> 29) & 0x3;
        let immhi = (raw >> 5) & 0x7FFFF;
        let rd = (raw & 0x1F) as u8;

        let imm = ((immhi << 2) | immlo) as i64;
        // Sign extend 21-bit value
        let imm = if imm & (1 << 20) != 0 {
            imm | !0x1FFFFF
        } else {
            imm
        };

        // ADR: op=0, forms PC + imm
        // ADRP: op=1, forms (PC & ~0xFFF) + (imm << 12)
        let (mnemonic, label) = if op == 0 {
            (Mnemonic::ADR, imm)
        } else {
            (Mnemonic::ADRP, imm << 12)
        };

        let insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::x(rd)))
            .with_operand(Operand::Label(label));

        Ok(insn)
    }

    fn decode_add_sub_imm(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let sf = (raw >> 31) & 1;
        let op = (raw >> 30) & 1;
        let s = (raw >> 29) & 1;
        let sh = (raw >> 22) & 1;
        let imm12 = ((raw >> 10) & 0xFFF) as i64;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;

        let is_64bit = sf == 1;
        let shift = if sh == 1 { 12 } else { 0 };

        // Determine mnemonic
        let mnemonic = match (op, s) {
            (0, 0) => Mnemonic::ADD,
            (0, 1) => Mnemonic::ADDS,
            (1, 0) => Mnemonic::SUB,
            (1, 1) => Mnemonic::SUBS,
            _ => unreachable!(),
        };

        // Check for aliases
        // CMN is ADDS with Rd = XZR/WZR
        // CMP is SUBS with Rd = XZR/WZR
        // MOV (to/from SP) is ADD with imm=0 and one operand is SP
        let (mnemonic, skip_rd, skip_imm) = if s == 1 && rd == 31 {
            if op == 0 {
                (Mnemonic::CMN, true, false)
            } else {
                (Mnemonic::CMP, true, false)
            }
        } else if op == 0 && s == 0 && sh == 0 && imm12 == 0 && (rd == 31 || rn == 31) {
            (Mnemonic::MOV, false, true)
        } else {
            (mnemonic, false, false)
        };

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4);

        if s == 1 {
            insn.sets_flags = true;
        }

        if !skip_rd {
            // For ADD/SUB, Rd can be SP
            insn = insn.with_operand(Operand::Reg(Register::with_sp(rd, is_64bit)));
        }

        // Rn can be SP for ADD/SUB immediate
        insn = insn.with_operand(Operand::Reg(Register::with_sp(rn, is_64bit)));
        if !skip_imm {
            insn = insn.with_operand(Operand::Imm(Immediate::shifted(imm12, shift)));
        }

        Ok(insn)
    }

    fn decode_add_sub_imm_tags(raw: u32) -> Result<DecodedInsn, DecodeError> {
        // MTE instructions: ADDG, SUBG
        let sf = (raw >> 31) & 1;
        let op = (raw >> 30) & 1;
        let s = (raw >> 29) & 1;
        let o2 = (raw >> 22) & 1;

        if sf == 0 || s == 1 || o2 == 1 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        let mnemonic = if op == 0 {
            Mnemonic::ADDG
        } else {
            Mnemonic::SUBG
        };

        let uimm6 = ((raw >> 16) & 0x3F) as i64;
        let uimm4 = ((raw >> 10) & 0xF) as i64;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_sp(rd, true)))
            .with_operand(Operand::Reg(Register::with_sp(rn, true)))
            .with_operand(Operand::Imm(Immediate::new(uimm6 << 4)))
            .with_operand(Operand::Imm(Immediate::new(uimm4))))
    }

    fn decode_logical_imm(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let sf = (raw >> 31) & 1;
        let opc = (raw >> 29) & 0x3;
        let n = (raw >> 22) & 1;
        let immr = ((raw >> 16) & 0x3F) as u8;
        let imms = ((raw >> 10) & 0x3F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;

        let is_64bit = sf == 1;

        // For 32-bit, N must be 0
        if !is_64bit && n == 1 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        let mnemonic = match opc {
            0b00 => Mnemonic::AND,
            0b01 => Mnemonic::ORR,
            0b10 => Mnemonic::EOR,
            0b11 => Mnemonic::ANDS,
            _ => unreachable!(),
        };

        // Decode bitmask immediate
        let Some(imm) = Self::decode_bitmask_imm(n as u8, imms, immr, is_64bit) else {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        };

        // Check for aliases
        // TST is ANDS with Rd = XZR/WZR
        // MOV (bitmask immediate) is ORR with Rn = XZR/WZR
        let (mnemonic, skip_rd) = if opc == 0b11 && rd == 31 {
            (Mnemonic::TST, true)
        } else if opc == 0b01 && rn == 31 && !Self::move_wide_preferred(imm, is_64bit) {
            (Mnemonic::MOV, false)
        } else {
            (mnemonic, false)
        };

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4);

        if opc == 0b11 {
            insn.sets_flags = true;
        }

        if !skip_rd {
            // For logical immediate, Rd can be SP only for AND/ORR/EOR (not ANDS)
            if opc != 0b11 {
                insn = insn.with_operand(Operand::Reg(Register::with_sp(rd, is_64bit)));
            } else {
                insn = insn.with_operand(Operand::Reg(Register::with_zr(rd, is_64bit)));
            }
        }

        if mnemonic != Mnemonic::MOV {
            insn = insn.with_operand(Operand::Reg(Register::with_zr(rn, is_64bit)));
        }

        insn = insn.with_operand(Operand::Imm(Immediate::new(imm as i64)));

        Ok(insn)
    }

    fn move_wide_preferred(imm: u64, is_64bit: bool) -> bool {
        let width = if is_64bit { 64 } else { 32 };
        let mask = if is_64bit { u64::MAX } else { u32::MAX as u64 };
        let value = imm & mask;
        let inverted = (!value) & mask;

        for shift in (0..width).step_by(16) {
            let chunk_mask = 0xffffu64 << shift;
            if value & !chunk_mask == 0 {
                return true;
            }
            if inverted & !chunk_mask == 0 {
                return true;
            }
        }

        false
    }

    fn decode_bitmask_imm(n: u8, imms: u8, immr: u8, is_64bit: bool) -> Option<u64> {
        // Decode the bitmask immediate encoding
        let len = if n != 0 {
            6
        } else {
            // Find highest bit set in ~imms
            let not_imms = !imms & 0x3F;
            if not_imms == 0 {
                return None;
            }
            (0..6).rev().find(|&i| (not_imms >> i) & 1 == 1)?
        };

        if len < 1 {
            return None;
        }

        let levels = (1u64 << len) - 1;
        let s = (imms as u64) & levels;
        let r = (immr as u64) & levels;
        let esize = 1u64 << len;

        if s == levels {
            return None;
        }

        // Create the basic pattern
        let welem = (1u64 << (s + 1)) - 1;

        // Rotate right
        let pattern = if esize == 64 {
            welem.rotate_right(r as u32)
        } else if r == 0 {
            welem
        } else {
            let mask = (1u64 << esize) - 1;
            ((welem >> r) | (welem << (esize - r))) & mask
        };

        // Replicate the pattern
        let mut result = pattern;
        let mut pos = esize;
        while pos < 64 {
            result |= pattern << pos;
            pos += esize;
        }

        if !is_64bit {
            result &= 0xFFFFFFFF;
        }

        Some(result)
    }

    fn decode_move_wide_imm(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let sf = (raw >> 31) & 1;
        let opc = (raw >> 29) & 0x3;
        let hw = ((raw >> 21) & 0x3) as u8;
        let imm16 = ((raw >> 5) & 0xFFFF) as i64;
        let rd = (raw & 0x1F) as u8;

        let is_64bit = sf == 1;

        // For 32-bit, hw must be 0 or 1
        if !is_64bit && hw >= 2 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        let mnemonic = match opc {
            0b00 => Mnemonic::MOVN,
            0b10 => Mnemonic::MOVZ,
            0b11 => Mnemonic::MOVK,
            _ => {
                return Ok(DecodedInsn::new(
                    Mnemonic::UNDEFINED,
                    ExecutionState::Aarch64,
                    raw,
                    4,
                ));
            }
        };

        let shift = hw * 16;

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_zr(rd, is_64bit)))
            .with_operand(Operand::Imm(Immediate::shifted(imm16, shift))))
    }

    fn decode_bitfield(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let sf = (raw >> 31) & 1;
        let opc = (raw >> 29) & 0x3;
        let n = (raw >> 22) & 1;
        let immr = ((raw >> 16) & 0x3F) as u8;
        let imms = ((raw >> 10) & 0x3F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;

        let is_64bit = sf == 1;

        // sf and N must match
        if sf != n {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }
        if !is_64bit && (immr >= 32 || imms >= 32) {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        let base_mnemonic = match opc {
            0b00 => Mnemonic::SBFM,
            0b01 => Mnemonic::BFI, // Actually BFM, but we'll determine alias
            0b10 => Mnemonic::UBFM,
            _ => {
                return Ok(DecodedInsn::new(
                    Mnemonic::UNDEFINED,
                    ExecutionState::Aarch64,
                    raw,
                    4,
                ));
            }
        };

        // Determine aliases based on immr/imms values
        let reg_size = if is_64bit { 64 } else { 32 };

        let mnemonic = match opc {
            0b00 => {
                // SBFM aliases
                if imms == (reg_size - 1) as u8 {
                    Mnemonic::ASR // ASR when imms == regsize-1
                } else if imms < immr {
                    Mnemonic::SBFIZ
                } else if immr == 0 {
                    match imms {
                        7 => Mnemonic::SXTB,
                        15 => Mnemonic::SXTH,
                        31 => Mnemonic::SXTW,
                        _ => Mnemonic::SBFX,
                    }
                } else {
                    Mnemonic::SBFX
                }
            }
            0b01 => {
                // BFM aliases
                if imms < immr {
                    if rn == 31 {
                        Mnemonic::BFC // BFC when Rn == WZR/XZR
                    } else {
                        Mnemonic::BFI
                    }
                } else {
                    Mnemonic::BFXIL
                }
            }
            0b10 => {
                // UBFM aliases
                if imms == (reg_size - 1) as u8 {
                    Mnemonic::LSR // LSR when imms == regsize-1
                } else if imms + 1 == immr {
                    Mnemonic::LSL // LSL when imms+1 == immr
                } else if imms < immr {
                    Mnemonic::UBFIZ
                } else if immr == 0 {
                    match imms {
                        7 if !is_64bit => Mnemonic::UXTB,
                        15 if !is_64bit => Mnemonic::UXTH,
                        _ => Mnemonic::UBFX,
                    }
                } else {
                    Mnemonic::UBFX
                }
            }
            _ => base_mnemonic,
        };

        if matches!(mnemonic, Mnemonic::SXTB | Mnemonic::SXTH) {
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                .with_operand(Operand::Reg(Register::with_zr(rd, is_64bit)))
                .with_operand(Operand::Reg(Register::with_zr(rn, false))));
        }

        if matches!(mnemonic, Mnemonic::UXTB | Mnemonic::UXTH) {
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                .with_operand(Operand::Reg(Register::with_zr(rd, false)))
                .with_operand(Operand::Reg(Register::with_zr(rn, false))));
        }

        if mnemonic == Mnemonic::SXTW {
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                .with_operand(Operand::Reg(Register::with_zr(rd, true)))
                .with_operand(Operand::Reg(Register::with_zr(rn, false))));
        }

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_zr(rd, is_64bit)))
            .with_operand(Operand::Reg(Register::with_zr(rn, is_64bit)))
            .with_operand(Operand::Imm(Immediate::new(immr as i64)))
            .with_operand(Operand::Imm(Immediate::new(imms as i64))))
    }

    fn decode_extract(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let sf = (raw >> 31) & 1;
        let opc = (raw >> 29) & 0x3;
        let n = (raw >> 22) & 1;
        let rm = ((raw >> 16) & 0x1F) as u8;
        let imms = ((raw >> 10) & 0x3F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;

        let is_64bit = sf == 1;

        if opc != 0 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        // sf and N must match
        if sf != n {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        // For 32-bit, imms must be < 32
        if !is_64bit && imms >= 32 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        // ROR is EXTR when Rn == Rm
        let mnemonic = if rn == rm {
            Mnemonic::ROR
        } else {
            Mnemonic::EXTR
        };

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_zr(rd, is_64bit)))
            .with_operand(Operand::Reg(Register::with_zr(rn, is_64bit)));

        if mnemonic == Mnemonic::EXTR {
            insn = insn.with_operand(Operand::Reg(Register::with_zr(rm, is_64bit)));
        }

        insn = insn.with_operand(Operand::Imm(Immediate::new(imms as i64)));

        Ok(insn)
    }

    // =========================================================================
    // Branch, Exception, and System
    // =========================================================================

    fn decode_branch_sys(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let op0 = (raw >> 29) & 0x7;
        let op1 = (raw >> 22) & 0x7F;
        let op_bit25 = (raw >> 25) & 0x1; // Bit 25 distinguishes CBZ/CBNZ from TBZ/TBNZ

        match op0 {
            // Unconditional branch (immediate)
            0b000 | 0b100 => Self::decode_uncond_branch_imm(raw),
            // Compare and branch (bit 25 = 0) or Test and branch (bit 25 = 1)
            0b001 | 0b011 | 0b101 | 0b111 => {
                if op_bit25 == 0 {
                    Self::decode_compare_branch(raw)
                } else {
                    Self::decode_test_branch(raw)
                }
            }
            // Conditional branch
            0b010 => Self::decode_cond_branch(raw),
            // System, exception, unconditional branch (register)
            0b110 => {
                // Check bits [31:24] for instruction type
                let top8 = (raw >> 24) & 0xFF;
                match top8 {
                    // Exception generating: 1101 0100 xxx = 0xD4
                    0xD4 => Self::decode_exception(raw),
                    // System: 1101 0101 0xx = 0xD5 with bit 22 = 0
                    0xD5 if (raw >> 22) & 1 == 0 => Self::decode_system(raw),
                    // Unconditional branch (register): 1101 011x = 0xD6/0xD7
                    0xD6 | 0xD7 => Self::decode_uncond_branch_reg(raw),
                    _ => Ok(DecodedInsn::new(
                        Mnemonic::UNKNOWN,
                        ExecutionState::Aarch64,
                        raw,
                        4,
                    )),
                }
            }
            _ => Ok(DecodedInsn::new(
                Mnemonic::UNKNOWN,
                ExecutionState::Aarch64,
                raw,
                4,
            )),
        }
    }

    fn decode_uncond_branch_imm(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let op = (raw >> 31) & 1;
        let imm26 = (raw & 0x3FFFFFF) as i64;

        // Sign extend 26-bit offset
        let offset = if imm26 & (1 << 25) != 0 {
            (imm26 | !0x3FFFFFF) << 2
        } else {
            imm26 << 2
        };

        let mnemonic = if op == 0 { Mnemonic::B } else { Mnemonic::BL };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Label(offset)))
    }

    fn decode_compare_branch(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let sf = (raw >> 31) & 1;
        let op = (raw >> 24) & 1;
        let imm19 = ((raw >> 5) & 0x7FFFF) as i64;
        let rt = (raw & 0x1F) as u8;

        let is_64bit = sf == 1;

        // Sign extend 19-bit offset
        let offset = if imm19 & (1 << 18) != 0 {
            (imm19 | !0x7FFFF) << 2
        } else {
            imm19 << 2
        };

        let mnemonic = if op == 0 {
            Mnemonic::CBZ
        } else {
            Mnemonic::CBNZ
        };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_zr(rt, is_64bit)))
            .with_operand(Operand::Label(offset)))
    }

    fn decode_test_branch(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let b5 = (raw >> 31) & 1;
        let op = (raw >> 24) & 1;
        let b40 = ((raw >> 19) & 0x1F) as u8;
        let imm14 = ((raw >> 5) & 0x3FFF) as i64;
        let rt = (raw & 0x1F) as u8;

        let bit_pos = (b5 << 5) as u8 | b40;
        let is_64bit = b5 == 1;

        // Sign extend 14-bit offset
        let offset = if imm14 & (1 << 13) != 0 {
            (imm14 | !0x3FFF) << 2
        } else {
            imm14 << 2
        };

        let mnemonic = if op == 0 {
            Mnemonic::TBZ
        } else {
            Mnemonic::TBNZ
        };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_zr(rt, is_64bit)))
            .with_operand(Operand::Imm(Immediate::new(bit_pos as i64)))
            .with_operand(Operand::Label(offset)))
    }

    fn decode_cond_branch(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let o1 = (raw >> 24) & 1;
        let imm19 = ((raw >> 5) & 0x7FFFF) as i64;
        let o0 = (raw >> 4) & 1;
        let cond = (raw & 0xF) as u8;

        if o1 != 0 || o0 != 0 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        // Sign extend 19-bit offset
        let offset = if imm19 & (1 << 18) != 0 {
            (imm19 | !0x7FFFF) << 2
        } else {
            imm19 << 2
        };

        Ok(
            DecodedInsn::new(Mnemonic::BCC, ExecutionState::Aarch64, raw, 4)
                .with_cond(Condition::from_bits(cond))
                .with_operand(Operand::Label(offset)),
        )
    }

    fn decode_exception(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let opc = (raw >> 21) & 0x7;
        let imm16 = ((raw >> 5) & 0xFFFF) as i64;
        let ll = raw & 0x3;

        let mnemonic = match (opc, ll) {
            (0b000, 0b01) => Mnemonic::SVC,
            (0b000, 0b10) => Mnemonic::HVC,
            (0b000, 0b11) => Mnemonic::SMC,
            (0b001, 0b00) => Mnemonic::BRK,
            (0b010, 0b00) => Mnemonic::HLT,
            (0b101, 0b01) => Mnemonic::UDF, // DCPS1
            (0b101, 0b10) => Mnemonic::UDF, // DCPS2
            (0b101, 0b11) => Mnemonic::UDF, // DCPS3
            _ => Mnemonic::UNDEFINED,
        };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Imm(Immediate::new(imm16))))
    }

    fn decode_system(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let l = (raw >> 21) & 1;
        let op0 = (raw >> 19) & 0x3;
        let op1 = ((raw >> 16) & 0x7) as u8;
        let crn = ((raw >> 12) & 0xF) as u8;
        let crm = ((raw >> 8) & 0xF) as u8;
        let op2 = ((raw >> 5) & 0x7) as u8;
        let rt = (raw & 0x1F) as u8;

        // Flag manipulation system instructions.
        if op0 == 0 && op1 == 0 && crn == 4 && crm == 0 && rt == 31 {
            let mnemonic = match op2 {
                0b000 => Mnemonic::CFINV,
                0b001 => Mnemonic::XAFLAG,
                0b010 => Mnemonic::AXFLAG,
                _ => Mnemonic::UNDEFINED,
            };
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4));
        }

        // FEAT_WFxT: WFET/WFIT use Rt as the timeout register.
        if op0 == 0 && op1 == 3 && crn == 1 && crm == 0 && matches!(op2, 0b000 | 0b001) {
            let mnemonic = if op2 == 0 {
                Mnemonic::WFET
            } else {
                Mnemonic::WFIT
            };
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                .with_operand(Operand::Reg(Register::with_zr(rt, true))));
        }

        // Hints: op0 = 0, op1 = 3, CRn = 2, Rt = 31
        if op0 == 0 && op1 == 3 && crn == 2 && rt == 31 {
            return Self::decode_hint_barrier(raw, op1, crm, op2, rt);
        }

        // Barriers: op0 = 0, op1 = 3, CRn = 3, Rt = 31
        if op0 == 0 && op1 == 3 && crn == 3 && rt == 31 {
            return Self::decode_barrier(raw, crm, op2);
        }

        // MSR/MRS (op0 >= 2)
        if op0 >= 2 {
            let sysreg = ((op0 as u16) << 14)
                | ((op1 as u16) << 11)
                | ((crn as u16) << 7)
                | ((crm as u16) << 3)
                | (op2 as u16);

            if l == 0 {
                // MSR
                Ok(
                    DecodedInsn::new(Mnemonic::MSR, ExecutionState::Aarch64, raw, 4)
                        .with_operand(Operand::SysReg(sysreg))
                        .with_operand(Operand::Reg(Register::with_zr(rt, true))),
                )
            } else {
                // MRS
                Ok(
                    DecodedInsn::new(Mnemonic::MRS, ExecutionState::Aarch64, raw, 4)
                        .with_operand(Operand::Reg(Register::with_zr(rt, true)))
                        .with_operand(Operand::SysReg(sysreg)),
                )
            }
        } else {
            Ok(DecodedInsn::new(
                Mnemonic::SYS,
                ExecutionState::Aarch64,
                raw,
                4,
            ))
        }
    }

    fn decode_ldr_literal(raw: u32) -> Result<DecodedInsn, DecodeError> {
        // LDR (literal) - Load register from PC-relative address
        let opc = (raw >> 30) & 0x3;
        let v = (raw >> 26) & 1;
        let imm19 = ((raw >> 5) & 0x7FFFF) as i64;
        let rt = (raw & 0x1F) as u8;

        // Sign extend 19-bit offset
        let offset = if imm19 & (1 << 18) != 0 {
            (imm19 | !0x7FFFF) << 2
        } else {
            imm19 << 2
        };

        if opc == 0b11 && v == 0 {
            return Ok(
                DecodedInsn::new(Mnemonic::PRFM, ExecutionState::Aarch64, raw, 4)
                    .with_operand(Operand::Prfop(PrefetchOp::from_bits(rt)))
                    .with_operand(Operand::Label(offset)),
            );
        }

        let (mnemonic, is_64bit) = match (opc, v) {
            (0b00, 0) => (Mnemonic::LDR, false),  // LDR Wt
            (0b01, 0) => (Mnemonic::LDR, true),   // LDR Xt
            (0b10, 0) => (Mnemonic::LDRSW, true), // LDRSW
            (0b00, 1) => (Mnemonic::LDR, false),  // LDR St (SIMD)
            (0b01, 1) => (Mnemonic::LDR, true),   // LDR Dt (SIMD)
            (0b10, 1) => (Mnemonic::LDR, true),   // LDR Qt (SIMD)
            _ => (Mnemonic::UNKNOWN, true),
        };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_zr(rt, is_64bit)))
            .with_operand(Operand::Label(offset)))
    }

    fn decode_barrier(raw: u32, crm: u8, op2: u8) -> Result<DecodedInsn, DecodeError> {
        let mnemonic = match op2 {
            0b010 => Mnemonic::CLREX,
            0b100 => Mnemonic::DSB,
            0b101 => Mnemonic::DMB,
            0b110 => Mnemonic::ISB,
            0b111 => Mnemonic::SB,
            _ => Mnemonic::UNKNOWN,
        };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Barrier(BarrierOption::from_bits(crm))))
    }

    fn decode_hint_barrier(
        raw: u32,
        _op1: u8,
        crm: u8,
        op2: u8,
        rt: u8,
    ) -> Result<DecodedInsn, DecodeError> {
        // NOP, YIELD, WFE, WFI, SEV, SEVL, etc.
        if rt != 31 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        if let Some(mnemonic) = Self::pauth_hint_mnemonic((crm << 3) | op2) {
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4));
        }
        let mnemonic = match (crm, op2) {
            (0b0000, 0b000) => Mnemonic::NOP,
            (0b0000, 0b001) => Mnemonic::YIELD,
            (0b0000, 0b010) => Mnemonic::WFE,
            (0b0000, 0b011) => Mnemonic::WFI,
            (0b0000, 0b100) => Mnemonic::SEV,
            (0b0000, 0b101) => Mnemonic::SEVL,
            (0b0000, 0b110) => Mnemonic::DGH,
            (0b0010, 0b000) => Mnemonic::NOP, // ESB
            (0b0010, 0b001) => Mnemonic::NOP, // PSB CSYNC
            (0b0010, 0b010) => Mnemonic::NOP, // TSB CSYNC
            (0b0010, 0b100) => Mnemonic::NOP, // CSDB
            (0b0100, 0b000 | 0b010 | 0b100 | 0b110) => Mnemonic::BTI,
            _ => Mnemonic::HINT,
        };

        if mnemonic == Mnemonic::HINT {
            let imm = (crm << 3) | op2;
            Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                .with_operand(Operand::Imm(Immediate::new(imm as i64))))
        } else {
            Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4))
        }
    }

    // =========================================================================
    // Load/Store
    // =========================================================================

    fn decode_load_store(raw: u32) -> Result<DecodedInsn, DecodeError> {
        // AArch64 load/store encoding uses multiple bits for dispatch
        // bits [29:27] gives the major category
        let op_cat = (raw >> 27) & 0x7;

        // Check for load/store pair: bits [29:27] = 101
        // This needs to come before the 0b101 match for register!
        if op_cat == 0b101 {
            return Self::decode_load_store_pair(raw);
        }

        if (raw >> 31) & 1 == 0 && matches!((raw >> 24) & 0x3F, 0b001100 | 0b001101) {
            return Self::decode_simd_ldst(raw, (raw >> 30) & 1);
        }

        if (raw >> 24) & 0xFF == 0xD9 && !matches!((raw >> 21) & 0x7, 0 | 2 | 4 | 6) {
            return Self::decode_mte_tag_load_store(raw);
        }

        let bit26 = (raw >> 26) & 1;
        let bit24 = (raw >> 24) & 1;

        if op_cat == 0b011 && bit26 == 0 && bit24 == 1 && matches!((raw >> 21) & 0x7, 0 | 2 | 4 | 6)
        {
            return Self::decode_ordered_unscaled(raw);
        }

        match op_cat {
            // Exclusive, atomic, ordered: bits[29:27] = 00x, bit26 = 0, bit24 = 0.
            _ if op_cat & 0b110 == 0 && bit26 == 0 && bit24 == 0 => {
                Self::decode_load_store_exclusive(raw)
            }
            // 0b011: Load register literal
            0b011 => Self::decode_ldr_literal(raw),
            // 0b100, 0b110: Load/store register variants
            0b100 | 0b110 => Self::decode_load_store_register(raw),
            // 0b111: Load/store register unsigned offset
            0b111 => Self::decode_load_store_register(raw),
            _ => Ok(DecodedInsn::new(
                Mnemonic::UNKNOWN,
                ExecutionState::Aarch64,
                raw,
                4,
            )),
        }
    }

    fn decode_mte_tag_load_store(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let opc = (raw >> 22) & 0x3;
        let imm9 = ((raw >> 12) & 0x1FF) as i64;
        let imm9 = if imm9 & (1 << 8) != 0 {
            imm9 | !0x1FF
        } else {
            imm9
        };
        let op2 = (raw >> 10) & 0x3;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rt = (raw & 0x1F) as u8;
        let offset = imm9 << 4;

        if op2 == 0 {
            if opc != 0b01 {
                return Ok(DecodedInsn::new(
                    Mnemonic::UNKNOWN,
                    ExecutionState::Aarch64,
                    raw,
                    4,
                ));
            }
            return Ok(
                DecodedInsn::new(Mnemonic::LDG, ExecutionState::Aarch64, raw, 4)
                    .with_operand(Operand::Reg(Register::with_zr(rt, true)))
                    .with_operand(Operand::Mem(MemOperand::imm_offset(
                        Register::with_sp(rn, true),
                        offset,
                    ))),
            );
        }

        let mnemonic = match opc {
            0b00 => Mnemonic::STG,
            0b01 => Mnemonic::STZG,
            0b10 => Mnemonic::ST2G,
            0b11 => Mnemonic::STZ2G,
            _ => unreachable!(),
        };
        let mem = match op2 {
            0b01 => MemOperand::post_index(Register::with_sp(rn, true), offset),
            0b10 => MemOperand::imm_offset(Register::with_sp(rn, true), offset),
            0b11 => MemOperand::pre_index(Register::with_sp(rn, true), offset),
            _ => unreachable!(),
        };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_zr(rt, true)))
            .with_operand(Operand::Mem(mem)))
    }

    fn decode_load_store_exclusive(raw: u32) -> Result<DecodedInsn, DecodeError> {
        if (raw >> 24) & 0x3F != 0b001000 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        let size = (raw >> 30) & 0x3;
        let l = (raw >> 22) & 1;
        let o0 = (raw >> 15) & 1;
        let rs = ((raw >> 16) & 0x1F) as u8;
        let o1 = (raw >> 21) & 1;
        let o2 = (raw >> 23) & 1;
        let rt2 = ((raw >> 10) & 0x1F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rt = (raw & 0x1F) as u8;

        let is_64bit = size == 0b11;
        let is_pair = o1 == 1;
        let is_ordered_non_exclusive = o2 == 1;
        let is_ordered_exclusive = o0 == 1;

        if o2 == 1 && o1 == 1 {
            let mnemonic = match (l, o0) {
                (0, 0) => Mnemonic::CAS,
                (1, 0) => Mnemonic::CASA,
                (0, 1) => Mnemonic::CASL,
                (1, 1) => Mnemonic::CASAL,
                _ => unreachable!(),
            };
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                .with_operand(Operand::Reg(Register::with_zr(rs, is_64bit)))
                .with_operand(Operand::Reg(Register::with_zr(rt, is_64bit)))
                .with_operand(Operand::Mem(MemOperand::base(Register::with_sp(rn, true)))));
        }

        if o2 == 0 && o1 == 1 && (raw >> 31) & 1 == 0 && rt2 == 31 {
            let mnemonic = match (l, o0) {
                (0, 0) => Mnemonic::CASP,
                (1, 0) => Mnemonic::CASPA,
                (0, 1) => Mnemonic::CASPL,
                (1, 1) => Mnemonic::CASPAL,
                _ => unreachable!(),
            };
            let is_64bit = ((raw >> 30) & 1) != 0;
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                .with_operand(Operand::Reg(Register::with_zr(rs, is_64bit)))
                .with_operand(Operand::Reg(Register::with_zr(rs + 1, is_64bit)))
                .with_operand(Operand::Reg(Register::with_zr(rt, is_64bit)))
                .with_operand(Operand::Reg(Register::with_zr(rt + 1, is_64bit)))
                .with_operand(Operand::Mem(MemOperand::base(Register::with_sp(rn, true)))));
        }

        let mnemonic = match (
            l,
            is_pair,
            is_ordered_non_exclusive,
            is_ordered_exclusive,
            size,
        ) {
            // Load exclusive
            (1, false, false, false, 0b00) => Mnemonic::LDXRB,
            (1, false, false, false, 0b01) => Mnemonic::LDXRH,
            (1, false, false, false, _) => Mnemonic::LDXR,
            // Load-acquire exclusive
            (1, false, false, true, 0b00) => Mnemonic::LDAXRB,
            (1, false, false, true, 0b01) => Mnemonic::LDAXRH,
            (1, false, false, true, _) => Mnemonic::LDAXR,
            // Load-acquire
            (1, false, true, true, 0b00) => Mnemonic::LDARB,
            (1, false, true, true, 0b01) => Mnemonic::LDARH,
            (1, false, true, true, _) => Mnemonic::LDAR,
            // LORegion load-acquire
            (1, false, true, false, 0b00) => Mnemonic::LDLARB,
            (1, false, true, false, 0b01) => Mnemonic::LDLARH,
            (1, false, true, false, _) => Mnemonic::LDLAR,
            // Load exclusive pair
            (1, true, false, false, _) => Mnemonic::LDXP,
            (1, true, false, true, _) => Mnemonic::LDAXP,
            // Store exclusive
            (0, false, false, false, 0b00) => Mnemonic::STXRB,
            (0, false, false, false, 0b01) => Mnemonic::STXRH,
            (0, false, false, false, _) => Mnemonic::STXR,
            // Store-release exclusive
            (0, false, false, true, 0b00) => Mnemonic::STLXRB,
            (0, false, false, true, 0b01) => Mnemonic::STLXRH,
            (0, false, false, true, _) => Mnemonic::STLXR,
            // Store-release
            (0, false, true, true, 0b00) => Mnemonic::STLRB,
            (0, false, true, true, 0b01) => Mnemonic::STLRH,
            (0, false, true, true, _) => Mnemonic::STLR,
            // LORegion store-release
            (0, false, true, false, 0b00) => Mnemonic::STLLRB,
            (0, false, true, false, 0b01) => Mnemonic::STLLRH,
            (0, false, true, false, _) => Mnemonic::STLLR,
            // Store exclusive pair
            (0, true, false, false, _) => Mnemonic::STXP,
            (0, true, false, true, _) => Mnemonic::STLXP,
            _ => Mnemonic::UNKNOWN,
        };

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4);

        // For store-exclusive, Rs comes first. STLR uses o2=1 and has no
        // status register, while STLXR/STLXP still have Rs.
        if l == 0 && !is_ordered_non_exclusive {
            insn = insn.with_operand(Operand::Reg(Register::w(rs)));
        }

        insn = insn.with_operand(Operand::Reg(Register::with_zr(rt, is_64bit)));

        if is_pair {
            insn = insn.with_operand(Operand::Reg(Register::with_zr(rt2, is_64bit)));
        }

        insn = insn.with_operand(Operand::Mem(MemOperand::base(Register::with_sp(rn, true))));

        Ok(insn)
    }

    fn decode_load_store_pair(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let opc = (raw >> 30) & 0x3;
        let v = (raw >> 26) & 1;
        let mode = (raw >> 23) & 0x3;
        let l = (raw >> 22) & 1;
        let imm7 = ((raw >> 15) & 0x7F) as i64;
        let rt2 = ((raw >> 10) & 0x1F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rt = (raw & 0x1F) as u8;

        // Sign extend 7-bit immediate
        let imm7 = if imm7 & (1 << 6) != 0 {
            imm7 | !0x7F
        } else {
            imm7
        };

        if v == 0 && l == 0 && mode == 0b00 && opc == 0b01 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        let stgp = v == 0 && l == 0 && mode != 0b00 && opc == 0b01;
        let scale = if stgp {
            4
        } else if v == 0 {
            2 + (opc >> 1)
        } else {
            2 + opc
        };
        let offset = imm7 << scale;

        let is_64bit = stgp || opc & 1 == 1 || (opc == 0b10);

        let mnemonic = match (l, v, mode, opc) {
            // Integer no-allocate pair forms. The opc==01 form is not allocated.
            (1, 0, 0b00, 0b00 | 0b10) => Mnemonic::LDNP,
            (0, 0, 0b00, 0b00 | 0b10) => Mnemonic::STNP,
            (1, 0, 0b00, 0b11) => Mnemonic::LDTNP,
            (0, 0, 0b00, 0b11) => Mnemonic::STTNP,
            // Integer load pair
            (1, 0, _, 0b00) => Mnemonic::LDP,
            (1, 0, 0b01 | 0b10 | 0b11, 0b01) => Mnemonic::LDPSW,
            (1, 0, _, 0b10) => Mnemonic::LDP,
            (1, 0, 0b01 | 0b10 | 0b11, 0b11) => Mnemonic::LDTP,
            // Integer store pair
            (0, 0, _, 0b00 | 0b10) => Mnemonic::STP,
            (0, 0, 0b01 | 0b10 | 0b11, 0b01) => Mnemonic::STGP,
            (0, 0, 0b01 | 0b10 | 0b11, 0b11) => Mnemonic::STTP,
            // SIMD load/store pair
            (1, 1, _, _) => Mnemonic::LDP,
            (0, 1, _, _) => Mnemonic::STP,
            _ => Mnemonic::UNKNOWN,
        };

        let addr_mode = match mode {
            0b01 => AddressingMode::PostIndex,
            0b10 => AddressingMode::Offset,
            0b11 => AddressingMode::PreIndex,
            _ => AddressingMode::Offset,
        };

        let mem = MemOperand {
            base: Register::with_sp(rn, true),
            offset: MemOffset::Imm(offset),
            mode: addr_mode,
        };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_zr(rt, is_64bit)))
            .with_operand(Operand::Reg(Register::with_zr(rt2, is_64bit)))
            .with_operand(Operand::Mem(mem)))
    }

    fn decode_load_store_register(raw: u32) -> Result<DecodedInsn, DecodeError> {
        if let Some(insn) = Self::decode_pauth_load(raw) {
            return Ok(insn);
        }
        let size = (raw >> 30) & 0x3;
        let v = (raw >> 26) & 1;
        let opc = (raw >> 22) & 0x3;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rt = (raw & 0x1F) as u8;

        // Determine if unsigned offset or other addressing mode
        let op2 = (raw >> 10) & 0x3;
        let addr_class = (raw >> 24) & 0x3;

        let is_unsigned_imm = addr_class == 0b01;
        let bit21 = (raw >> 21) & 1;
        let is_signed_offset = !is_unsigned_imm && bit21 == 0 && op2 == 0b00;
        let is_register_offset = !is_unsigned_imm && bit21 == 1 && op2 == 0b10;

        // Atomic memory operations (FEAT_LSE): size 111 0 00 A R 1 Rs o3 opc 00 Rn Rt.
        if v == 0 && ((raw >> 24) & 1) == 0 && bit21 == 1 && op2 == 0b00 {
            return Self::decode_atomic_memory(raw);
        }

        if v == 0 && !is_unsigned_imm && bit21 == 0 && op2 == 0b10 {
            return Self::decode_unprivileged_load_store(raw);
        }

        if v == 0 && size == 0b11 && opc == 0b10 {
            let mem = if is_unsigned_imm {
                let imm12 = ((raw >> 10) & 0xFFF) as i64;
                MemOperand::imm_offset(Register::with_sp(rn, true), imm12 << 3)
            } else if is_signed_offset {
                let imm9 = ((raw >> 12) & 0x1FF) as i64;
                let imm9 = if imm9 & (1 << 8) != 0 {
                    imm9 | !0x1FF
                } else {
                    imm9
                };
                MemOperand::imm_offset(Register::with_sp(rn, true), imm9)
            } else if is_register_offset {
                let rm = ((raw >> 16) & 0x1F) as u8;
                let option = ((raw >> 13) & 0x7) as u8;
                if option & 0b010 == 0 {
                    return Ok(DecodedInsn::new(
                        Mnemonic::UNKNOWN,
                        ExecutionState::Aarch64,
                        raw,
                        4,
                    ));
                }
                let shift = if ((raw >> 12) & 1) != 0 { 3 } else { 0 };
                let rm_is_64bit = option & 0x3 == 0x3;
                MemOperand {
                    base: Register::with_sp(rn, true),
                    offset: MemOffset::ExtendedReg(ExtendedRegister::new(
                        Register::with_zr(rm, rm_is_64bit),
                        ExtendType::from_bits(option),
                        shift,
                    )),
                    mode: AddressingMode::Offset,
                }
            } else {
                return Ok(DecodedInsn::new(
                    Mnemonic::UNKNOWN,
                    ExecutionState::Aarch64,
                    raw,
                    4,
                ));
            };

            return Ok(
                DecodedInsn::new(Mnemonic::PRFM, ExecutionState::Aarch64, raw, 4)
                    .with_operand(Operand::Prfop(PrefetchOp::from_bits(rt)))
                    .with_operand(Operand::Mem(mem)),
            );
        }

        let (mnemonic, is_64bit) = match (size, v, opc) {
            // Byte
            (0b00, 0, 0b00) => (Mnemonic::STRB, false),
            (0b00, 0, 0b01) => (Mnemonic::LDRB, false),
            (0b00, 0, 0b10) => (Mnemonic::LDRSB, true), // 64-bit sign-extend
            (0b00, 0, 0b11) => (Mnemonic::LDRSB, false), // 32-bit sign-extend
            // Halfword
            (0b01, 0, 0b00) => (Mnemonic::STRH, false),
            (0b01, 0, 0b01) => (Mnemonic::LDRH, false),
            (0b01, 0, 0b10) => (Mnemonic::LDRSH, true),
            (0b01, 0, 0b11) => (Mnemonic::LDRSH, false),
            // Word
            (0b10, 0, 0b00) => (Mnemonic::STR, false),
            (0b10, 0, 0b01) => (Mnemonic::LDR, false),
            (0b10, 0, 0b10) => (Mnemonic::LDRSW, true),
            // Doubleword
            (0b11, 0, 0b00) => (Mnemonic::STR, true),
            (0b11, 0, 0b01) => (Mnemonic::LDR, true),
            // SIMD
            (_, 1, _) => {
                let is_load = opc & 1 == 1;
                if is_load {
                    (Mnemonic::LDR, true)
                } else {
                    (Mnemonic::STR, true)
                }
            }
            _ => (Mnemonic::UNKNOWN, false),
        };

        // SIMD&FP load/store (V=1): the access size is `opc[1]:size` (B/H/S/D/Q),
        // and Rt names an FP/vector register, not a GPR. (Previously these
        // decoded as GPR LDR/STR with the wrong size — the "SIMD load as GPR"
        // bug that mis-executed vector loads in the interpreter and blocked
        // vector-memory JIT.)
        let simd_fp_size = if v == 1 {
            match ((opc >> 1) & 1, size) {
                (0, 0b00) => Some(FpRegSize::B),
                (0, 0b01) => Some(FpRegSize::H),
                (0, 0b10) => Some(FpRegSize::S),
                (0, 0b11) => Some(FpRegSize::D),
                (1, 0b00) => Some(FpRegSize::Q),
                _ => {
                    return Ok(DecodedInsn::new(
                        Mnemonic::UNKNOWN,
                        ExecutionState::Aarch64,
                        raw,
                        4,
                    ));
                }
            }
        } else {
            None
        };
        // Offset scale = log2(access bytes). For GPR this is `size`; for SIMD it
        // is derived from the FP size (size==00 for Q would otherwise scale by 0).
        let mem_scale = match simd_fp_size {
            Some(FpRegSize::B) => 0,
            Some(FpRegSize::H) => 1,
            Some(FpRegSize::S) => 2,
            Some(FpRegSize::D) => 3,
            Some(FpRegSize::Q) => 4,
            _ => size as i64,
        };

        let mem = if is_unsigned_imm {
            let imm12 = ((raw >> 10) & 0xFFF) as i64;
            let offset = imm12 << mem_scale;
            MemOperand::imm_offset(Register::with_sp(rn, true), offset)
        } else if is_register_offset {
            let rm = ((raw >> 16) & 0x1F) as u8;
            let option = ((raw >> 13) & 0x7) as u8;
            if option & 0b010 == 0 {
                return Ok(DecodedInsn::new(
                    Mnemonic::UNKNOWN,
                    ExecutionState::Aarch64,
                    raw,
                    4,
                ));
            }
            let shift = if ((raw >> 12) & 1) != 0 {
                mem_scale as u8
            } else {
                0
            };
            let rm_is_64bit = option & 0x3 == 0x3;
            MemOperand {
                base: Register::with_sp(rn, true),
                offset: MemOffset::ExtendedReg(ExtendedRegister::new(
                    Register::with_zr(rm, rm_is_64bit),
                    ExtendType::from_bits(option),
                    shift,
                )),
                mode: AddressingMode::Offset,
            }
        } else {
            let imm9 = ((raw >> 12) & 0x1FF) as i64;
            let imm9 = if imm9 & (1 << 8) != 0 {
                imm9 | !0x1FF
            } else {
                imm9
            };

            match op2 {
                0b00 | 0b10 => MemOperand::imm_offset(Register::with_sp(rn, true), imm9),
                0b01 => MemOperand::post_index(Register::with_sp(rn, true), imm9),
                0b11 => MemOperand::pre_index(Register::with_sp(rn, true), imm9),
                _ => unreachable!(),
            }
        };

        let rt_operand = match simd_fp_size {
            Some(fp_size) => Operand::FpReg(FpRegister {
                num: rt,
                size: fp_size,
            }),
            None => Operand::Reg(Register::with_zr(rt, is_64bit)),
        };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(rt_operand)
            .with_operand(Operand::Mem(mem)))
    }

    fn decode_unprivileged_load_store(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let size = (raw >> 30) & 0x3;
        let opc = (raw >> 22) & 0x3;
        let imm9 = ((raw >> 12) & 0x1FF) as i64;
        let imm9 = if imm9 & (1 << 8) != 0 {
            imm9 | !0x1FF
        } else {
            imm9
        };
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rt = (raw & 0x1F) as u8;

        let (mnemonic, is_64bit) = match (size, opc) {
            (0b00, 0b00) => (Mnemonic::STTRB, false),
            (0b01, 0b00) => (Mnemonic::STTRH, false),
            (0b10, 0b00) => (Mnemonic::STTR, false),
            (0b11, 0b00) => (Mnemonic::STTR, true),
            (0b00, 0b01) => (Mnemonic::LDTRB, false),
            (0b01, 0b01) => (Mnemonic::LDTRH, false),
            (0b10, 0b01) => (Mnemonic::LDTR, false),
            (0b11, 0b01) => (Mnemonic::LDTR, true),
            (0b00, 0b10) => (Mnemonic::LDTRSB, true),
            (0b01, 0b10) => (Mnemonic::LDTRSH, true),
            (0b10, 0b10) => (Mnemonic::LDTRSW, true),
            (0b00, 0b11) => (Mnemonic::LDTRSB, false),
            (0b01, 0b11) => (Mnemonic::LDTRSH, false),
            _ => {
                return Ok(DecodedInsn::new(
                    Mnemonic::UNDEFINED,
                    ExecutionState::Aarch64,
                    raw,
                    4,
                ));
            }
        };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_zr(rt, is_64bit)))
            .with_operand(Operand::Mem(MemOperand::imm_offset(
                Register::with_sp(rn, true),
                imm9,
            ))))
    }

    fn decode_ordered_unscaled(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let size = (raw >> 30) & 0x3;
        let opc = (raw >> 22) & 0x3;
        let imm9 = ((raw >> 12) & 0x1FF) as i64;
        let imm9 = if imm9 & (1 << 8) != 0 {
            imm9 | !0x1FF
        } else {
            imm9
        };
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rt = (raw & 0x1F) as u8;

        let (mnemonic, is_64bit) = match (size, opc) {
            (0b00, 0b00) => (Mnemonic::STLURB, false),
            (0b01, 0b00) => (Mnemonic::STLURH, false),
            (0b10, 0b00) => (Mnemonic::STLUR, false),
            (0b11, 0b00) => (Mnemonic::STLUR, true),
            (0b00, 0b01) => (Mnemonic::LDAPURB, false),
            (0b01, 0b01) => (Mnemonic::LDAPURH, false),
            (0b10, 0b01) => (Mnemonic::LDAPUR, false),
            (0b11, 0b01) => (Mnemonic::LDAPUR, true),
            (0b00, 0b10) => (Mnemonic::LDAPURSB, true),
            (0b01, 0b10) => (Mnemonic::LDAPURSH, true),
            (0b10, 0b10) => (Mnemonic::LDAPURSW, true),
            (0b00, 0b11) => (Mnemonic::LDAPURSB, false),
            (0b01, 0b11) => (Mnemonic::LDAPURSH, false),
            _ => {
                return Ok(DecodedInsn::new(
                    Mnemonic::UNDEFINED,
                    ExecutionState::Aarch64,
                    raw,
                    4,
                ));
            }
        };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_zr(rt, is_64bit)))
            .with_operand(Operand::Mem(MemOperand::imm_offset(
                Register::with_sp(rn, true),
                imm9,
            ))))
    }

    fn decode_atomic_memory(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let size = (raw >> 30) & 0x3;
        let acquire = ((raw >> 23) & 1) != 0;
        let release = ((raw >> 22) & 1) != 0;
        let rs = ((raw >> 16) & 0x1F) as u8;
        let o3 = (raw >> 15) & 1;
        let opc = (raw >> 12) & 0x7;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rt = (raw & 0x1F) as u8;
        let is_64bit = size == 0b11;

        let suffix = (acquire, release);
        if o3 == 1 && opc == 0b100 && suffix == (true, false) && rs == 31 {
            let mnemonic = match size {
                0b00 => Mnemonic::LDAPRB,
                0b01 => Mnemonic::LDAPRH,
                _ => Mnemonic::LDAPR,
            };
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                .with_operand(Operand::Reg(Register::with_zr(rt, is_64bit)))
                .with_operand(Operand::Mem(MemOperand::base(Register::with_sp(rn, true)))));
        }

        let mnemonic = if o3 == 1 {
            match (opc, suffix) {
                (0b000, (false, false)) => Mnemonic::SWP,
                (0b000, (true, false)) => Mnemonic::SWPA,
                (0b000, (false, true)) => Mnemonic::SWPL,
                (0b000, (true, true)) => Mnemonic::SWPAL,
                _ => Mnemonic::UNKNOWN,
            }
        } else {
            match (opc, suffix) {
                (0b000, (false, false)) => Mnemonic::LDADD,
                (0b000, (true, false)) => Mnemonic::LDADDA,
                (0b000, (false, true)) => Mnemonic::LDADDL,
                (0b000, (true, true)) => Mnemonic::LDADDAL,
                (0b001, _) => Mnemonic::LDCLR,
                (0b010, _) => Mnemonic::LDEOR,
                (0b011, _) => Mnemonic::LDSET,
                (0b100, _) => Mnemonic::LDSMAX,
                (0b101, _) => Mnemonic::LDSMIN,
                (0b110, _) => Mnemonic::LDUMAX,
                (0b111, _) => Mnemonic::LDUMIN,
                _ => Mnemonic::UNKNOWN,
            }
        };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_zr(rs, is_64bit)))
            .with_operand(Operand::Reg(Register::with_zr(rt, is_64bit)))
            .with_operand(Operand::Mem(MemOperand::base(Register::with_sp(rn, true)))))
    }

    // =========================================================================
    // Data Processing - Register
    // =========================================================================

    fn decode_dp_reg(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let op0 = (raw >> 30) & 1;
        let op1 = (raw >> 28) & 1;
        let op2 = (raw >> 21) & 0xF;

        if op1 == 0 {
            // Logical shifted register, add/sub shifted register, add/sub extended register
            // Logical: op2 = 0xxx (bit 24 = 0)
            // Add/sub shifted: op2 = 1xx0 (bit 24 = 1, bit 21 = 0)
            // Add/sub extended: op2 = 1xx1 (bit 24 = 1, bit 21 = 1)
            if (op2 & 0x8) == 0x0 {
                Self::decode_logical_shifted_reg(raw)
            } else if (op2 & 0x9) == 0x8 {
                Self::decode_add_sub_shifted_reg(raw)
            } else if op2 == 0b1001 {
                Self::decode_add_sub_extended_reg(raw)
            } else {
                Ok(DecodedInsn::new(
                    Mnemonic::UNKNOWN,
                    ExecutionState::Aarch64,
                    raw,
                    4,
                ))
            }
        } else {
            // Data processing (3 source), data processing (2 source), etc.
            if op2 == 0b0110 {
                if op0 == 0 {
                    Self::decode_dp_2_source(raw)
                } else {
                    Self::decode_dp_1_source(raw)
                }
            } else if op2 == 0b0000 {
                // Add/sub with carry
                Self::decode_add_sub_carry(raw)
            } else if op2 & 0xE == 0x2 {
                // Conditional compare
                Self::decode_cond_compare(raw)
            } else if op2 & 0xE == 0x4 {
                // Conditional select
                Self::decode_cond_select(raw)
            } else if op2 & 0x8 == 0x8 {
                // Data processing (3 source)
                Self::decode_dp_3_source(raw)
            } else {
                Ok(DecodedInsn::new(
                    Mnemonic::UNKNOWN,
                    ExecutionState::Aarch64,
                    raw,
                    4,
                ))
            }
        }
    }

    fn decode_logical_shifted_reg(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let sf = (raw >> 31) & 1;
        let opc = (raw >> 29) & 0x3;
        let shift = ShiftType::from_bits(((raw >> 22) & 0x3) as u8);
        let n = (raw >> 21) & 1;
        let rm = ((raw >> 16) & 0x1F) as u8;
        let imm6 = ((raw >> 10) & 0x3F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;

        let is_64bit = sf == 1;

        // For 32-bit, imm6 must be < 32
        if !is_64bit && imm6 >= 32 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        let mnemonic = match (opc, n) {
            (0b00, 0) => Mnemonic::AND,
            (0b00, 1) => Mnemonic::BIC,
            (0b01, 0) => Mnemonic::ORR,
            (0b01, 1) => Mnemonic::ORN,
            (0b10, 0) => Mnemonic::EOR,
            (0b10, 1) => Mnemonic::EON,
            (0b11, 0) => Mnemonic::ANDS,
            (0b11, 1) => Mnemonic::BICS,
            _ => unreachable!(),
        };

        // Check for aliases
        // MOV is ORR with Rn = XZR/WZR and shift = 0
        // MVN is ORN with Rn = XZR/WZR
        // TST is ANDS with Rd = XZR/WZR
        let (mnemonic, skip_rn, skip_rd) =
            if opc == 0b01 && n == 0 && rn == 31 && shift == ShiftType::LSL && imm6 == 0 {
                (Mnemonic::MOV, true, false)
            } else if opc == 0b01 && n == 1 && rn == 31 {
                (Mnemonic::MVN, true, false)
            } else if opc == 0b11 && n == 0 && rd == 31 {
                (Mnemonic::TST, false, true)
            } else {
                (mnemonic, false, false)
            };

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4);

        if opc == 0b11 {
            insn.sets_flags = true;
        }

        if !skip_rd {
            insn = insn.with_operand(Operand::Reg(Register::with_zr(rd, is_64bit)));
        }

        if !skip_rn {
            insn = insn.with_operand(Operand::Reg(Register::with_zr(rn, is_64bit)));
        }

        if imm6 == 0 && shift == ShiftType::LSL {
            insn = insn.with_operand(Operand::Reg(Register::with_zr(rm, is_64bit)));
        } else {
            insn = insn.with_operand(Operand::ShiftedReg(ShiftedRegister::new(
                Register::with_zr(rm, is_64bit),
                shift,
                imm6,
            )));
        }

        Ok(insn)
    }

    fn decode_add_sub_shifted_reg(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let sf = (raw >> 31) & 1;
        let op = (raw >> 30) & 1;
        let s = (raw >> 29) & 1;
        let shift = ShiftType::from_bits(((raw >> 22) & 0x3) as u8);
        let rm = ((raw >> 16) & 0x1F) as u8;
        let imm6 = ((raw >> 10) & 0x3F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;

        let is_64bit = sf == 1;

        // ROR is not allowed
        if shift == ShiftType::ROR {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        // For 32-bit, imm6 must be < 32
        if !is_64bit && imm6 >= 32 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        let mnemonic = match (op, s) {
            (0, 0) => Mnemonic::ADD,
            (0, 1) => Mnemonic::ADDS,
            (1, 0) => Mnemonic::SUB,
            (1, 1) => Mnemonic::SUBS,
            _ => unreachable!(),
        };

        // Check for aliases
        // NEG is SUB with Rn = XZR/WZR
        // NEGS is SUBS with Rn = XZR/WZR
        // CMP is SUBS with Rd = XZR/WZR
        // CMN is ADDS with Rd = XZR/WZR
        let (mnemonic, skip_rn, skip_rd) = if s == 1 && rd == 31 {
            if op == 0 {
                (Mnemonic::CMN, false, true)
            } else {
                (Mnemonic::CMP, false, true)
            }
        } else if op == 1 && rn == 31 {
            if s == 0 {
                (Mnemonic::NEG, true, false)
            } else {
                (Mnemonic::NEGS, true, false)
            }
        } else {
            (mnemonic, false, false)
        };

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4);

        if s == 1 {
            insn.sets_flags = true;
        }

        if !skip_rd {
            insn = insn.with_operand(Operand::Reg(Register::with_zr(rd, is_64bit)));
        }

        if !skip_rn {
            insn = insn.with_operand(Operand::Reg(Register::with_zr(rn, is_64bit)));
        }

        if imm6 == 0 && shift == ShiftType::LSL {
            insn = insn.with_operand(Operand::Reg(Register::with_zr(rm, is_64bit)));
        } else {
            insn = insn.with_operand(Operand::ShiftedReg(ShiftedRegister::new(
                Register::with_zr(rm, is_64bit),
                shift,
                imm6,
            )));
        }

        Ok(insn)
    }

    fn decode_add_sub_extended_reg(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let sf = (raw >> 31) & 1;
        let op = (raw >> 30) & 1;
        let s = (raw >> 29) & 1;
        let rm = ((raw >> 16) & 0x1F) as u8;
        let option = ((raw >> 13) & 0x7) as u8;
        let imm3 = ((raw >> 10) & 0x7) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;

        let is_64bit = sf == 1;

        // imm3 must be <= 4
        if imm3 > 4 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        let mnemonic = match (op, s) {
            (0, 0) => Mnemonic::ADD,
            (0, 1) => Mnemonic::ADDS,
            (1, 0) => Mnemonic::SUB,
            (1, 1) => Mnemonic::SUBS,
            _ => unreachable!(),
        };

        // Check for CMP/CMN aliases
        let (mnemonic, skip_rd) = if s == 1 && rd == 31 {
            if op == 0 {
                (Mnemonic::CMN, true)
            } else {
                (Mnemonic::CMP, true)
            }
        } else {
            (mnemonic, false)
        };

        let extend_type = ExtendType::from_bits(option);
        let rm_is_64bit = option & 0x3 == 0x3;

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4);

        if s == 1 {
            insn.sets_flags = true;
        }

        if !skip_rd {
            insn = insn.with_operand(Operand::Reg(Register::with_sp(rd, is_64bit)));
        }

        insn = insn.with_operand(Operand::Reg(Register::with_sp(rn, is_64bit)));
        insn = insn.with_operand(Operand::ExtendedReg(ExtendedRegister::new(
            Register::with_zr(rm, rm_is_64bit),
            extend_type,
            imm3,
        )));

        Ok(insn)
    }

    fn decode_add_sub_carry(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let sf = (raw >> 31) & 1;
        let op = (raw >> 30) & 1;
        let s = (raw >> 29) & 1;
        let rm = ((raw >> 16) & 0x1F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;

        let is_64bit = sf == 1;

        let mnemonic = match (op, s) {
            (0, 0) => Mnemonic::ADC,
            (0, 1) => Mnemonic::ADCS,
            (1, 0) => Mnemonic::SBC,
            (1, 1) => Mnemonic::SBCS,
            _ => unreachable!(),
        };

        let (mnemonic, skip_rn) = if op == 1 && rn == 31 {
            if s == 0 {
                (Mnemonic::NGC, true)
            } else {
                (Mnemonic::NGCS, true)
            }
        } else {
            (mnemonic, false)
        };

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4);

        if s == 1 {
            insn.sets_flags = true;
        }

        insn = insn.with_operand(Operand::Reg(Register::with_zr(rd, is_64bit)));

        if !skip_rn {
            insn = insn.with_operand(Operand::Reg(Register::with_zr(rn, is_64bit)));
        }
        insn = insn.with_operand(Operand::Reg(Register::with_zr(rm, is_64bit)));

        Ok(insn)
    }

    fn decode_cond_compare(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let sf = (raw >> 31) & 1;
        let op = (raw >> 30) & 1;
        let s = (raw >> 29) & 1;
        let o2 = (raw >> 10) & 1;
        let o3 = (raw >> 4) & 1;
        let rm_or_imm = ((raw >> 16) & 0x1F) as u8;
        let cond = ((raw >> 12) & 0xF) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let nzcv = (raw & 0xF) as u8;
        let is_imm = (raw >> 11) & 1 == 1;

        if s == 0 || o2 != 0 || o3 != 0 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        let is_64bit = sf == 1;
        let mnemonic = if op == 0 {
            Mnemonic::CCMN
        } else {
            Mnemonic::CCMP
        };

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_zr(rn, is_64bit)));

        if is_imm {
            insn = insn.with_operand(Operand::Imm(Immediate::new(rm_or_imm as i64)));
        } else {
            insn = insn.with_operand(Operand::Reg(Register::with_zr(rm_or_imm, is_64bit)));
        }

        insn = insn.with_operand(Operand::Imm(Immediate::new(nzcv as i64)));
        insn = insn.with_operand(Operand::Cond(Condition::from_bits(cond)));

        Ok(insn)
    }

    fn decode_cond_select(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let sf = (raw >> 31) & 1;
        let op = (raw >> 30) & 1;
        let s = (raw >> 29) & 1;
        let rm = ((raw >> 16) & 0x1F) as u8;
        let cond = ((raw >> 12) & 0xF) as u8;
        let op2 = (raw >> 10) & 0x3;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;

        if s != 0 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        let is_64bit = sf == 1;

        let mnemonic = match (op, op2) {
            (0, 0b00) => Mnemonic::CSEL,
            (0, 0b01) => Mnemonic::CSINC,
            (1, 0b00) => Mnemonic::CSINV,
            (1, 0b01) => Mnemonic::CSNEG,
            _ => {
                return Ok(DecodedInsn::new(
                    Mnemonic::UNDEFINED,
                    ExecutionState::Aarch64,
                    raw,
                    4,
                ));
            }
        };

        // Check for aliases
        // CSET is CSINC with Rn = Rm = XZR and inverted condition
        // CSETM is CSINV with Rn = Rm = XZR and inverted condition
        // CINC is CSINC with Rn = Rm and inverted condition
        // CINV is CSINV with Rn = Rm and inverted condition
        // CNEG is CSNEG with Rn = Rm and inverted condition
        let mnemonic = if rn == 31 && rm == 31 {
            match (op, op2) {
                (0, 0b01) => Mnemonic::CSET,
                (1, 0b00) => Mnemonic::CSETM,
                _ => mnemonic,
            }
        } else if rn == rm {
            match (op, op2) {
                (0, 0b01) => Mnemonic::CINC,
                (1, 0b00) => Mnemonic::CINV,
                (1, 0b01) => Mnemonic::CNEG,
                _ => mnemonic,
            }
        } else {
            mnemonic
        };

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_zr(rd, is_64bit)));

        // For CSET/CSETM, don't add Rn/Rm.
        let is_cset_alias = rn == 31 && rm == 31 && matches!((op, op2), (0, 0b01) | (1, 0b00));
        if !is_cset_alias {
            insn = insn.with_operand(Operand::Reg(Register::with_zr(rn, is_64bit)));

            // For CINC/CINV/CNEG, don't add Rm (it's same as Rn)
            if !(rn == rm && matches!(mnemonic, Mnemonic::CINC | Mnemonic::CINV | Mnemonic::CNEG)) {
                insn = insn.with_operand(Operand::Reg(Register::with_zr(rm, is_64bit)));
            }
        }

        let condition = Condition::from_bits(cond);
        let condition = if matches!(
            mnemonic,
            Mnemonic::CSET | Mnemonic::CSETM | Mnemonic::CINC | Mnemonic::CINV | Mnemonic::CNEG
        ) {
            condition.invert()
        } else {
            condition
        };
        insn = insn.with_operand(Operand::Cond(condition));

        Ok(insn)
    }

    fn decode_dp_2_source(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let sf = (raw >> 31) & 1;
        let s = (raw >> 29) & 1;
        let rm = ((raw >> 16) & 0x1F) as u8;
        let opcode = (raw >> 10) & 0x3F;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;

        if s != 0 && !(sf == 1 && opcode == 0b000000) {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        let is_64bit = sf == 1;

        let mnemonic = match opcode {
            0b000010 => Mnemonic::UDIV,
            0b000011 => Mnemonic::SDIV,
            0b001000 => Mnemonic::LSL,
            0b001001 => Mnemonic::LSR,
            0b001010 => Mnemonic::ASR,
            0b001011 => Mnemonic::ROR,
            // CRC32
            0b010000 if !is_64bit => Mnemonic::CRC32B,
            0b010001 if !is_64bit => Mnemonic::CRC32H,
            0b010010 if !is_64bit => Mnemonic::CRC32W,
            0b010011 if is_64bit => Mnemonic::CRC32X,
            0b010100 if !is_64bit => Mnemonic::CRC32CB,
            0b010101 if !is_64bit => Mnemonic::CRC32CH,
            0b010110 if !is_64bit => Mnemonic::CRC32CW,
            0b010111 if is_64bit => Mnemonic::CRC32CX,
            0b000000 if is_64bit && s == 0 => Mnemonic::SUBP,
            0b000000 if is_64bit && s == 1 => Mnemonic::SUBPS,
            0b000100 if is_64bit && s == 0 => Mnemonic::IRG,
            0b000101 if is_64bit && s == 0 => Mnemonic::GMI,
            // PAC
            0b001100 if is_64bit && s == 0 => Mnemonic::PACGA,
            _ => Mnemonic::UNKNOWN,
        };

        if matches!(
            mnemonic,
            Mnemonic::CRC32B
                | Mnemonic::CRC32H
                | Mnemonic::CRC32W
                | Mnemonic::CRC32X
                | Mnemonic::CRC32CB
                | Mnemonic::CRC32CH
                | Mnemonic::CRC32CW
                | Mnemonic::CRC32CX
        ) {
            let source_is_64bit = matches!(mnemonic, Mnemonic::CRC32X | Mnemonic::CRC32CX);
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                .with_operand(Operand::Reg(Register::with_zr(rd, false)))
                .with_operand(Operand::Reg(Register::with_zr(rn, false)))
                .with_operand(Operand::Reg(Register::with_zr(rm, source_is_64bit))));
        }

        if matches!(mnemonic, Mnemonic::SUBP | Mnemonic::SUBPS) {
            let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                .with_operand(Operand::Reg(Register::with_zr(rd, true)))
                .with_operand(Operand::Reg(Register::with_sp(rn, true)))
                .with_operand(Operand::Reg(Register::with_sp(rm, true)));
            if mnemonic == Mnemonic::SUBPS {
                insn.sets_flags = true;
            }
            return Ok(insn);
        }

        if mnemonic == Mnemonic::IRG {
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                .with_operand(Operand::Reg(Register::with_sp(rd, true)))
                .with_operand(Operand::Reg(Register::with_sp(rn, true)))
                .with_operand(Operand::Reg(Register::with_zr(rm, true))));
        }

        if mnemonic == Mnemonic::GMI {
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                .with_operand(Operand::Reg(Register::with_zr(rd, true)))
                .with_operand(Operand::Reg(Register::with_sp(rn, true)))
                .with_operand(Operand::Reg(Register::with_zr(rm, true))));
        }

        if mnemonic == Mnemonic::PACGA {
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                .with_operand(Operand::Reg(Register::with_zr(rd, true)))
                .with_operand(Operand::Reg(Register::with_zr(rn, true)))
                .with_operand(Operand::Reg(Register::with_sp(rm, true))));
        }

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_zr(rd, is_64bit)))
            .with_operand(Operand::Reg(Register::with_zr(rn, is_64bit)))
            .with_operand(Operand::Reg(Register::with_zr(rm, is_64bit))))
    }

    fn decode_dp_1_source(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let sf = (raw >> 31) & 1;
        let s = (raw >> 29) & 1;
        let opcode2 = (raw >> 16) & 0x1F;
        let opcode = (raw >> 10) & 0x3F;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;

        if s != 0 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        if sf == 1 && opcode2 == 0b00001 {
            let mnemonic = match opcode {
                0b000000 => Mnemonic::PACIA,
                0b000001 => Mnemonic::PACIB,
                0b000010 => Mnemonic::PACDA,
                0b000011 => Mnemonic::PACDB,
                0b000100 => Mnemonic::AUTIA,
                0b000101 => Mnemonic::AUTIB,
                0b000110 => Mnemonic::AUTDA,
                0b000111 => Mnemonic::AUTDB,
                0b001000 => Mnemonic::PACIZA,
                0b001001 => Mnemonic::PACIZB,
                0b001010 => Mnemonic::PACDZA,
                0b001011 => Mnemonic::PACDZB,
                0b001100 => Mnemonic::AUTIZA,
                0b001101 => Mnemonic::AUTIZB,
                0b001110 => Mnemonic::AUTDZA,
                0b001111 => Mnemonic::AUTDZB,
                0b010000 => Mnemonic::XPACI,
                0b010001 => Mnemonic::XPACD,
                _ => Mnemonic::UNDEFINED,
            };

            if mnemonic == Mnemonic::UNDEFINED {
                return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4));
            }

            let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                .with_operand(Operand::Reg(Register::with_zr(rd, true)));
            if opcode <= 0b000111 {
                insn = insn.with_operand(Operand::Reg(Register::with_sp(rn, true)));
            } else if rn != 31 {
                return Ok(DecodedInsn::new(
                    Mnemonic::UNDEFINED,
                    ExecutionState::Aarch64,
                    raw,
                    4,
                ));
            }
            return Ok(insn);
        }

        if opcode2 != 0 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNKNOWN,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        let is_64bit = sf == 1;
        let mnemonic = match opcode {
            0b000000 => Mnemonic::RBIT,
            0b000001 => Mnemonic::REV16,
            0b000010 if is_64bit => Mnemonic::REV32,
            0b000010 => Mnemonic::REV,
            0b000011 if is_64bit => Mnemonic::REV,
            0b000100 => Mnemonic::CLZ,
            0b000101 => Mnemonic::CLS,
            _ => Mnemonic::UNKNOWN,
        };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_zr(rd, is_64bit)))
            .with_operand(Operand::Reg(Register::with_zr(rn, is_64bit))))
    }

    fn decode_dp_3_source(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let sf = (raw >> 31) & 1;
        let op54 = (raw >> 29) & 0x3;
        let op31 = (raw >> 21) & 0x7;
        let rm = ((raw >> 16) & 0x1F) as u8;
        let o0 = (raw >> 15) & 1;
        let ra = ((raw >> 10) & 0x1F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;

        if op54 != 0 {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        }

        let is_64bit = sf == 1;

        let mnemonic = match (sf, op31, o0) {
            (_, 0b000, 0) => Mnemonic::MADD,
            (_, 0b000, 1) => Mnemonic::MSUB,
            (1, 0b001, 0) => Mnemonic::SMADDL,
            (1, 0b001, 1) => Mnemonic::SMSUBL,
            (1, 0b010, 0) => Mnemonic::SMULH,
            (1, 0b101, 0) => Mnemonic::UMADDL,
            (1, 0b101, 1) => Mnemonic::UMSUBL,
            (1, 0b110, 0) => Mnemonic::UMULH,
            _ => Mnemonic::UNDEFINED,
        };

        // Check for MUL/MNEG aliases
        // MUL is MADD with Ra = XZR
        // MNEG is MSUB with Ra = XZR
        let (mnemonic, skip_ra) = if matches!(mnemonic, Mnemonic::SMULH | Mnemonic::UMULH) {
            (mnemonic, true)
        } else if ra == 31 {
            match mnemonic {
                Mnemonic::MADD => (Mnemonic::MUL, true),
                Mnemonic::MSUB => (Mnemonic::MNEG, true),
                Mnemonic::SMADDL => (Mnemonic::SMULL, true),
                Mnemonic::SMSUBL => (Mnemonic::SMNEGL, true),
                Mnemonic::UMADDL => (Mnemonic::UMULL, true),
                Mnemonic::UMSUBL => (Mnemonic::UMNEGL, true),
                _ => (mnemonic, false),
            }
        } else {
            (mnemonic, false)
        };

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(Operand::Reg(Register::with_zr(rd, is_64bit)));

        // For long multiplies, Rn and Rm are 32-bit
        let src_64bit = if matches!(
            mnemonic,
            Mnemonic::SMADDL
                | Mnemonic::SMSUBL
                | Mnemonic::UMADDL
                | Mnemonic::UMSUBL
                | Mnemonic::SMULL
                | Mnemonic::UMULL
                | Mnemonic::SMNEGL
                | Mnemonic::UMNEGL
        ) {
            false
        } else {
            is_64bit
        };

        insn = insn.with_operand(Operand::Reg(Register::with_zr(rn, src_64bit)));
        insn = insn.with_operand(Operand::Reg(Register::with_zr(rm, src_64bit)));

        if !skip_ra {
            insn = insn.with_operand(Operand::Reg(Register::with_zr(ra, is_64bit)));
        }

        Ok(insn)
    }

    // =========================================================================
    // SIMD and FP
    // =========================================================================

    pub(super) fn scalar_fp_size(ptype: u32) -> Option<FpRegSize> {
        match ptype {
            0b00 => Some(FpRegSize::S),
            0b01 => Some(FpRegSize::D),
            0b11 => Some(FpRegSize::H),
            _ => None,
        }
    }

    pub(super) fn decode_scalar_fp(raw: u32) -> Result<DecodedInsn, DecodeError> {
        if (raw >> 21) & 1 == 0 {
            return Self::decode_scalar_fp_legacy(raw);
        }

        // Scalar FP immediate (FMOV #imm). The decoder has no FP-immediate
        // operand representation, so leave valid forms for the interpreter
        // instead of emitting an FMOV that the lifter treats as register-source.
        if (raw >> 10) & 0x7 == 0b100 && (raw >> 5) & 0x1F == 0 {
            return Self::decode_scalar_fp_immediate(raw);
        }

        if (raw >> 10) & 0x3 == 0b10 {
            return Self::decode_scalar_fp_2source(raw);
        }

        if (raw >> 10) & 0x1F == 0b10000 {
            return Self::decode_scalar_fp_1source(raw);
        }

        if (raw >> 14) & 0x3 == 0 && (raw >> 10) & 0xF == 0b1000 && (raw & 0x7) == 0 {
            return Self::decode_scalar_fp_compare(raw);
        }

        if (raw >> 10) & 0x3 == 0b01 {
            return Self::decode_scalar_fp_cond_compare(raw);
        }

        if (raw >> 10) & 0x3 == 0b11 {
            return Self::decode_scalar_fp_cond_select(raw);
        }

        Ok(DecodedInsn::new(
            Mnemonic::UNKNOWN,
            ExecutionState::Aarch64,
            raw,
            4,
        ))
    }

    fn decode_scalar_fp_legacy(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let ptype = (raw >> 22) & 0x3;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;

        let Some(fp_size) = Self::scalar_fp_size(ptype) else {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        };
        let fp_reg = |num, size| Operand::FpReg(FpRegister { num, size });

        let mnemonic = Mnemonic::FMOV;

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(fp_reg(rd, fp_size))
            .with_operand(fp_reg(rn, fp_size)))
    }

    fn decode_scalar_fp_immediate(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let ptype = (raw >> 22) & 0x3;
        let mnemonic = if Self::scalar_fp_size(ptype).is_some() {
            Mnemonic::UNKNOWN
        } else {
            Mnemonic::UNDEFINED
        };
        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4))
    }

    fn decode_scalar_fp_1source(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let ptype = (raw >> 22) & 0x3;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;
        let opc6 = (raw >> 15) & 0x3F;

        let Some(fp_size) = Self::scalar_fp_size(ptype) else {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        };
        let fp_reg = |num, size| Operand::FpReg(FpRegister { num, size });

        let mnemonic = match opc6 {
            0b000000 => Mnemonic::FMOV,
            0b000001 => Mnemonic::FABS,
            0b000010 => Mnemonic::FNEG,
            0b000011 => Mnemonic::FSQRT,
            0b000100 | 0b000101 | 0b000111 => Mnemonic::FCVT,
            0b001000 => Mnemonic::FRINTN,
            0b001001 => Mnemonic::FRINTP,
            0b001010 => Mnemonic::FRINTM,
            0b001011 => Mnemonic::FRINTZ,
            0b001100 => Mnemonic::FRINTA,
            0b001110 => Mnemonic::FRINTX,
            0b001111 => Mnemonic::FRINTI,
            _ => Mnemonic::UNKNOWN,
        };

        if mnemonic == Mnemonic::UNKNOWN {
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4));
        }

        if mnemonic == Mnemonic::FCVT {
            let dst_size = match opc6 & 0b11 {
                0b00 => FpRegSize::S,
                0b01 => FpRegSize::D,
                0b11 => FpRegSize::H,
                _ => {
                    return Ok(DecodedInsn::new(
                        Mnemonic::UNDEFINED,
                        ExecutionState::Aarch64,
                        raw,
                        4,
                    ));
                }
            };
            if dst_size == fp_size {
                return Ok(DecodedInsn::new(
                    Mnemonic::UNDEFINED,
                    ExecutionState::Aarch64,
                    raw,
                    4,
                ));
            }
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                .with_operand(fp_reg(rd, dst_size))
                .with_operand(fp_reg(rn, fp_size)));
        }

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(fp_reg(rd, fp_size))
            .with_operand(fp_reg(rn, fp_size)))
    }

    fn decode_scalar_fp_2source(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let ptype = (raw >> 22) & 0x3;
        let rm = ((raw >> 16) & 0x1F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;
        let Some(fp_size) = Self::scalar_fp_size(ptype) else {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        };
        let fp_reg = |num, size| Operand::FpReg(FpRegister { num, size });

        let mnemonic = match (raw >> 12) & 0xF {
            0b0000 => Mnemonic::FMUL,
            0b0001 => Mnemonic::FDIV,
            0b0010 => Mnemonic::FADD,
            0b0011 => Mnemonic::FSUB,
            0b0100 => Mnemonic::FMAX,
            0b0101 => Mnemonic::FMIN,
            0b0110 => Mnemonic::FMAXNM,
            0b0111 => Mnemonic::FMINNM,
            0b1000 => Mnemonic::FNMUL,
            _ => Mnemonic::UNKNOWN,
        };

        if mnemonic == Mnemonic::UNKNOWN {
            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4));
        }

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(fp_reg(rd, fp_size))
            .with_operand(fp_reg(rn, fp_size))
            .with_operand(fp_reg(rm, fp_size)))
    }

    fn decode_scalar_fp_compare(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let ptype = (raw >> 22) & 0x3;
        let rm = ((raw >> 16) & 0x1F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;

        let Some(fp_size) = Self::scalar_fp_size(ptype) else {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        };

        let fp_reg = |num| Operand::FpReg(FpRegister { num, size: fp_size });
        let mnemonic = if (raw >> 4) & 1 == 1 {
            Mnemonic::FCMPE
        } else {
            Mnemonic::FCMP
        };

        let mut insn =
            DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4).with_operand(fp_reg(rn));
        if (raw & 0x8) == 0 {
            insn = insn.with_operand(fp_reg(rm));
        }
        Ok(insn)
    }

    fn decode_scalar_fp_cond_compare(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let ptype = (raw >> 22) & 0x3;
        let mnemonic = if Self::scalar_fp_size(ptype).is_some() {
            // FCCMP/FCCMPE need condition-false NZCV semantics in SMIR. Until
            // that is modeled, do not emit an actionable compare instruction.
            Mnemonic::UNKNOWN
        } else {
            Mnemonic::UNDEFINED
        };
        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4))
    }

    fn decode_scalar_fp_cond_select(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let ptype = (raw >> 22) & 0x3;
        let rm = ((raw >> 16) & 0x1F) as u8;
        let cond = ((raw >> 12) & 0xF) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let rd = (raw & 0x1F) as u8;

        let Some(fp_size) = Self::scalar_fp_size(ptype) else {
            return Ok(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch64,
                raw,
                4,
            ));
        };
        let fp_reg = |num| Operand::FpReg(FpRegister { num, size: fp_size });

        Ok(
            DecodedInsn::new(Mnemonic::FCSEL, ExecutionState::Aarch64, raw, 4)
                .with_operand(fp_reg(rd))
                .with_operand(fp_reg(rn))
                .with_operand(fp_reg(rm))
                .with_operand(Operand::Cond(Condition::from_bits(cond))),
        )
    }

    // =========================================================================
    // SVE
    // =========================================================================

    /// Decode SVE (Scalable Vector Extension) instructions.
    ///
    /// SVE encoding space: bits[28:25] = 0010
    /// Further classification by bits[24:21] and other fields.
    #[allow(clippy::bad_bit_mask)]
    fn decode_sve(raw: u32) -> Result<DecodedInsn, DecodeError> {
        // Extract primary classification bits
        let op0 = (raw >> 29) & 0x7; // bits[31:29]
        let op1 = (raw >> 23) & 0x3; // bits[24:23]
        let op2 = (raw >> 17) & 0x1F; // bits[21:17]
        let op3 = (raw >> 10) & 0x3F; // bits[15:10]

        // Common register fields
        let zd = (raw & 0x1F) as u8;
        let zn = ((raw >> 5) & 0x1F) as u8;
        let zm = ((raw >> 16) & 0x1F) as u8;
        let pg = ((raw >> 10) & 0x7) as u8; // predicate register (3 bits)
        let size = (raw >> 22) & 0x3; // element size

        // Create SVE register operands
        let sve_z = |num| Operand::Reg(Register::sve_z(num));
        let sve_p = |num| Operand::Reg(Register::sve_p(num));

        match op0 {
            // Integer multiply-add predicated
            0b000
                if (raw >> 24) & 0xFF == 0x04
                    && (raw >> 21) & 1 == 0
                    && matches!((raw >> 13) & 0x7, 0b010 | 0b011) =>
            {
                let op = (raw >> 13) & 1;
                let mnemonic = match op {
                    0 => Mnemonic::SVE_MLA,
                    1 => Mnemonic::SVE_MLS,
                    _ => unreachable!(),
                };
                Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                    .with_operand(sve_z(zd))
                    .with_operand(sve_p(pg))
                    .with_operand(sve_z(zn))
                    .with_operand(sve_z(zm)))
            }

            // Integer predicated binary operations
            0b000 if (op1 & 0x2) == 0 && (op2 & 0x10) == 0 && (op3 & 0x38) == 0 => {
                let opc = (raw >> 16) & 0x7;
                let mnemonic = match opc {
                    0b000 => Mnemonic::SVE_ADD,
                    0b001 => Mnemonic::SVE_SUB,
                    0b011 => Mnemonic::SVE_SUBR,
                    _ => Mnemonic::UNKNOWN,
                };
                Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                    .with_operand(sve_z(zd))
                    .with_operand(sve_p(pg))
                    .with_operand(sve_z(zn)))
            }

            // Integer min/max predicated
            0b000 if (op1 & 0x2) == 0 && (op2 & 0x18) == 0x08 => {
                let opc = (raw >> 17) & 0x3;
                let u = (raw >> 16) & 1;
                let mnemonic = match (opc, u) {
                    (0b00, 0) => Mnemonic::SVE_SMAX,
                    (0b00, 1) => Mnemonic::SVE_UMAX,
                    (0b01, 0) => Mnemonic::SVE_SMIN,
                    (0b01, 1) => Mnemonic::SVE_UMIN,
                    (0b10, 0) => Mnemonic::SVE_SABD,
                    (0b10, 1) => Mnemonic::SVE_UABD,
                    _ => Mnemonic::UNKNOWN,
                };
                Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                    .with_operand(sve_z(zd))
                    .with_operand(sve_p(pg))
                    .with_operand(sve_z(zm)))
            }

            // Integer multiply/divide predicated
            0b000 if (op1 & 0x2) == 0 && (op2 & 0x18) == 0x10 => {
                let h = (raw >> 17) & 1;
                let u = (raw >> 16) & 1;
                let mnemonic = match (h, u) {
                    (0, 0) => Mnemonic::SVE_MUL,
                    (1, 0) => Mnemonic::SVE_SMULH,
                    (1, 1) => Mnemonic::SVE_UMULH,
                    _ => Mnemonic::UNKNOWN,
                };
                Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                    .with_operand(sve_z(zd))
                    .with_operand(sve_p(pg))
                    .with_operand(sve_z(zm)))
            }

            // Integer divide predicated
            0b000 if (op1 & 0x2) == 0 && (op2 & 0x18) == 0x14 => {
                let r = (raw >> 17) & 1;
                let u = (raw >> 16) & 1;
                let mnemonic = match (r, u) {
                    (0, 0) => Mnemonic::SVE_SDIV,
                    (0, 1) => Mnemonic::SVE_UDIV,
                    _ => Mnemonic::UNKNOWN,
                };
                Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                    .with_operand(sve_z(zd))
                    .with_operand(sve_p(pg))
                    .with_operand(sve_z(zm)))
            }

            // Logical predicated
            0b000 if (op1 & 0x2) == 0 && (op2 & 0x18) == 0x18 => {
                let opc = (raw >> 16) & 0x7;
                let mnemonic = match opc {
                    0b000 => Mnemonic::SVE_ORR,
                    0b001 => Mnemonic::SVE_EOR,
                    0b010 => Mnemonic::SVE_AND,
                    0b011 => Mnemonic::SVE_BIC,
                    _ => Mnemonic::UNKNOWN,
                };
                Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                    .with_operand(sve_z(zd))
                    .with_operand(sve_p(pg))
                    .with_operand(sve_z(zm)))
            }

            // Unpredicated arithmetic
            0b000 if op1 == 0b01 => {
                let opc = (raw >> 10) & 0x7;
                let mnemonic = match opc {
                    0b000 => Mnemonic::SVE_ADD,
                    0b001 => Mnemonic::SVE_SUB,
                    0b100 => Mnemonic::SVE_MUL, // sqadd actually, simplified
                    _ => Mnemonic::UNKNOWN,
                };
                Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                    .with_operand(sve_z(zd))
                    .with_operand(sve_z(zn))
                    .with_operand(sve_z(zm)))
            }

            // Predicate operations
            0b001 if op1 == 0b00 => {
                // While instructions
                let lt = (raw >> 4) & 1;
                let sf = (raw >> 12) & 1;
                let mnemonic = if lt == 1 {
                    Mnemonic::SVE_WHILELT
                } else {
                    Mnemonic::SVE_WHILELE
                };
                let pd = (raw & 0xF) as u8;
                let rn = ((raw >> 5) & 0x1F) as u8;
                let rm = ((raw >> 16) & 0x1F) as u8;
                Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                    .with_operand(sve_p(pd))
                    .with_operand(Operand::Reg(if sf == 1 {
                        Register::x(rn)
                    } else {
                        Register::w(rn)
                    }))
                    .with_operand(Operand::Reg(if sf == 1 {
                        Register::x(rm)
                    } else {
                        Register::w(rm)
                    })))
            }

            // PTRUE/PTRUES
            0b001
                if (raw >> 24) & 0xFF == 0x25
                    && op2 == 0b01100
                    && op3 == 0b111000
                    && (raw >> 4) & 1 == 0 =>
            {
                let pd = (raw & 0xF) as u8;
                Ok(
                    DecodedInsn::new(Mnemonic::SVE_PTRUE, ExecutionState::Aarch64, raw, 4)
                        .with_operand(sve_p(pd)),
                )
            }

            // PFALSE
            0b001 if raw & 0xFFFF_FFF0 == 0x2518_E400 => {
                let pd = (raw & 0xF) as u8;
                Ok(
                    DecodedInsn::new(Mnemonic::SVE_PFALSE, ExecutionState::Aarch64, raw, 4)
                        .with_operand(sve_p(pd)),
                )
            }

            // DUP/SEL/MOV
            0b000 if op1 == 0b10 => {
                let mnemonic = Mnemonic::SVE_DUP;
                Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                    .with_operand(sve_z(zd))
                    .with_operand(sve_z(zn)))
            }

            // INDEX
            0b000 if op1 == 0b11 && (op2 & 0x10) == 0 => {
                let mnemonic = Mnemonic::SVE_INDEX;
                Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                    .with_operand(sve_z(zd))
                    .with_operand(Operand::Reg(Register::x(zn)))
                    .with_operand(Operand::Reg(Register::x(zm))))
            }

            // Count/Inc/Dec
            0b000 if op1 == 0b11 && (op2 & 0x18) == 0x10 => {
                let opc = (raw >> 16) & 0x7;
                let mnemonic = match opc {
                    0b000 => Mnemonic::SVE_CNTB,
                    0b001 => Mnemonic::SVE_CNTH,
                    0b010 => Mnemonic::SVE_CNTW,
                    0b011 => Mnemonic::SVE_CNTD,
                    _ => Mnemonic::UNKNOWN,
                };
                Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                    .with_operand(Operand::Reg(Register::x(zd))))
            }

            // Permute - ZIP/UZP/TRN
            0b000 if op1 == 0b10 && (op3 & 0x30) == 0x00 => {
                let opc = (raw >> 10) & 0x7;
                let mnemonic = match opc {
                    0b000 => Mnemonic::SVE_ZIP1,
                    0b001 => Mnemonic::SVE_ZIP2,
                    0b010 => Mnemonic::SVE_UZP1,
                    0b011 => Mnemonic::SVE_UZP2,
                    0b100 => Mnemonic::SVE_TRN1,
                    0b101 => Mnemonic::SVE_TRN2,
                    _ => Mnemonic::UNKNOWN,
                };
                Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                    .with_operand(sve_z(zd))
                    .with_operand(sve_z(zn))
                    .with_operand(sve_z(zm)))
            }

            // REV
            0b000 if op1 == 0b10 && (op3 & 0x38) == 0x18 => {
                let opc = (raw >> 16) & 0x3;
                let mnemonic = match opc {
                    0b00 => Mnemonic::SVE_REV,
                    0b01 => Mnemonic::SVE_REVB,
                    0b10 => Mnemonic::SVE_REVH,
                    0b11 => Mnemonic::SVE_REVW,
                    _ => Mnemonic::UNKNOWN,
                };
                Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                    .with_operand(sve_z(zd))
                    .with_operand(sve_z(zn)))
            }

            // Load/Store contiguous
            0b100 | 0b101 | 0b110 | 0b111 => Self::decode_sve_ldst(raw),

            // FP arithmetic predicated
            0b011 if (op1 & 0x2) == 0 => {
                let opc = (raw >> 16) & 0xF;
                let mnemonic = match opc {
                    0b0000 => Mnemonic::SVE_FADD,
                    0b0001 => Mnemonic::SVE_FSUB,
                    0b0010 => Mnemonic::SVE_FMUL,
                    0b0011 => Mnemonic::SVE_FDIV,
                    0b0100 => Mnemonic::SVE_FMIN,
                    0b0101 => Mnemonic::SVE_FMAX,
                    0b1000 => Mnemonic::SVE_FABS,
                    0b1001 => Mnemonic::SVE_FNEG,
                    0b1010 => Mnemonic::SVE_FSQRT,
                    _ => Mnemonic::UNKNOWN,
                };
                Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                    .with_operand(sve_z(zd))
                    .with_operand(sve_p(pg))
                    .with_operand(sve_z(zn)))
            }

            // FP multiply-add predicated
            0b011 if op1 == 0b01 => {
                let op = (raw >> 13) & 1;
                let mnemonic = match op {
                    0 => Mnemonic::SVE_FMLA,
                    1 => Mnemonic::SVE_FMLS,
                    _ => unreachable!(),
                };
                Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                    .with_operand(sve_z(zd))
                    .with_operand(sve_p(pg))
                    .with_operand(sve_z(zn))
                    .with_operand(sve_z(zm)))
            }

            // Reduction operations
            0b000 if (op1 & 0x2) == 0x2 && (op3 & 0x20) != 0 => {
                let opc = (raw >> 16) & 0x7;
                let u = (raw >> 19) & 1;
                let mnemonic = match (opc, u) {
                    (0b000, 0) => Mnemonic::SVE_SADDV,
                    (0b000, 1) => Mnemonic::SVE_UADDV,
                    (0b001, 0) => Mnemonic::SVE_SMAXV,
                    (0b001, 1) => Mnemonic::SVE_UMAXV,
                    (0b010, 0) => Mnemonic::SVE_SMINV,
                    (0b010, 1) => Mnemonic::SVE_UMINV,
                    (0b011, _) => Mnemonic::SVE_ANDV,
                    (0b100, _) => Mnemonic::SVE_ORV,
                    (0b101, _) => Mnemonic::SVE_EORV,
                    _ => Mnemonic::UNKNOWN,
                };
                let vd = zd; // destination is a scalar V register
                Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                    .with_operand(Operand::FpReg(FpRegister {
                        num: vd,
                        size: FpRegSize::D,
                    }))
                    .with_operand(sve_p(pg))
                    .with_operand(sve_z(zn)))
            }

            // RDVL - read vector length
            0b000 if op1 == 0b11 && op2 == 0x1F && (op3 & 0x3E) == 0x10 => {
                let rd = zd;
                let imm6 = ((raw >> 5) & 0x3F) as i8;
                // Sign extend
                let imm = if imm6 & 0x20 != 0 {
                    imm6 as i64 | !0x3F
                } else {
                    imm6 as i64
                };
                Ok(
                    DecodedInsn::new(Mnemonic::SVE_RDVL, ExecutionState::Aarch64, raw, 4)
                        .with_operand(Operand::Reg(Register::x(rd)))
                        .with_operand(Operand::Imm(Immediate::new(imm))),
                )
            }

            // Fallback for unrecognized patterns
            _ => Ok(DecodedInsn::new(
                Mnemonic::UNKNOWN,
                ExecutionState::Aarch64,
                raw,
                4,
            )),
        }
    }

    /// Decode SVE load/store instructions.
    fn decode_sve_ldst(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let op0 = (raw >> 29) & 0x7;
        let msz = (raw >> 23) & 0x3; // memory element size
        let opc = (raw >> 21) & 0x3;

        let zt = (raw & 0x1F) as u8;
        let rn = ((raw >> 5) & 0x1F) as u8;
        let pg = ((raw >> 10) & 0x7) as u8;

        let sve_z = |num| Operand::Reg(Register::sve_z(num));
        let sve_p = |num| Operand::Reg(Register::sve_p(num));

        // Determine if load or store and element size
        let is_load = (op0 & 0x1) == 0;

        let mnemonic = if is_load {
            match msz {
                0b00 => Mnemonic::SVE_LD1B,
                0b01 => Mnemonic::SVE_LD1H,
                0b10 => Mnemonic::SVE_LD1W,
                0b11 => Mnemonic::SVE_LD1D,
                _ => Mnemonic::SVE_LD1,
            }
        } else {
            match msz {
                0b00 => Mnemonic::SVE_ST1B,
                0b01 => Mnemonic::SVE_ST1H,
                0b10 => Mnemonic::SVE_ST1W,
                0b11 => Mnemonic::SVE_ST1D,
                _ => Mnemonic::SVE_ST1,
            }
        };

        // Extract immediate offset if present
        let imm4 = ((raw >> 16) & 0xF) as i64;
        let offset = if imm4 & 0x8 != 0 {
            imm4 | !0xF // sign extend
        } else {
            imm4
        };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
            .with_operand(sve_z(zt))
            .with_operand(sve_p(pg))
            .with_operand(Operand::Mem(MemOperand::base_offset(
                Register::x(rn),
                offset * (1 << msz), // scale by element size
            ))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to decode little-endian bytes
    fn decode_bytes(bytes: &[u8; 4]) -> Result<DecodedInsn, DecodeError> {
        let raw = u32::from_le_bytes(*bytes);
        Aarch64Decoder::decode(raw)
    }

    fn logical_imm_raw(sf: u32, opc: u32, n: u32, immr: u32, imms: u32, rn: u32, rd: u32) -> u32 {
        (sf << 31)
            | (opc << 29)
            | (0b100100 << 23)
            | (n << 22)
            | (immr << 16)
            | (imms << 10)
            | (rn << 5)
            | rd
    }

    fn ordered_ldst_raw(size: u32, load: bool, rs: u32, rt2: u32) -> u32 {
        let l = if load { 1 } else { 0 };

        (size << 30)
            | (0b001000 << 24)
            | (1 << 23)
            | (l << 22)
            | (rs << 16)
            | (1 << 15)
            | (rt2 << 10)
            | (1 << 5)
            | 3
    }

    #[test]
    fn test_nop() {
        // NOP: d503201f
        let insn = decode_bytes(&[0x1f, 0x20, 0x03, 0xd5]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::NOP);
        assert_eq!(insn.size, 4);
    }

    #[test]
    fn test_ret() {
        // RET: d65f03c0
        let insn = decode_bytes(&[0xc0, 0x03, 0x5f, 0xd6]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::RET);
    }

    #[test]
    fn test_mov_imm() {
        // MOV X0, #1 -> MOVZ X0, #1: d2800020
        let insn = decode_bytes(&[0x20, 0x00, 0x80, 0xd2]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::MOVZ);
        assert_eq!(insn.operands.len(), 2);
    }

    #[test]
    fn test_add_imm() {
        // ADD X0, X1, #0x10: 91004020
        let insn = decode_bytes(&[0x20, 0x40, 0x00, 0x91]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::ADD);
        assert_eq!(insn.operands.len(), 3);
    }

    #[test]
    fn test_add_imm_zero_sp_aliases_to_mov() {
        for (bytes, dst, src) in [
            ([0xe0, 0x03, 0x00, 0x91], Register::x(0), Register::sp(true)),
            ([0x1f, 0x00, 0x00, 0x91], Register::sp(true), Register::x(0)),
            (
                [0xff, 0x03, 0x00, 0x91],
                Register::sp(true),
                Register::sp(true),
            ),
            (
                [0xe0, 0x03, 0x00, 0x11],
                Register::w(0),
                Register::sp(false),
            ),
            (
                [0x1f, 0x00, 0x00, 0x11],
                Register::sp(false),
                Register::w(0),
            ),
        ] {
            let insn = decode_bytes(&bytes).unwrap();
            assert_eq!(insn.mnemonic, Mnemonic::MOV);
            assert_eq!(insn.operands.len(), 2);
            assert!(matches!(insn.operands.get(0), Some(Operand::Reg(reg)) if *reg == dst));
            assert!(matches!(insn.operands.get(1), Some(Operand::Reg(reg)) if *reg == src));
        }

        let add = decode_bytes(&[0x20, 0x00, 0x00, 0x91]).unwrap();
        assert_eq!(add.mnemonic, Mnemonic::ADD);
        assert_eq!(add.operands.len(), 3);
    }

    #[test]
    fn test_logical_imm_64bit_rotation_decode() {
        // AND X0, X1, #0x8000_0000_0000_0000. This uses N=1, so the
        // bitmask element size is 64 bits and the rotate path must not build
        // a 1<<64 mask.
        let insn = Aarch64Decoder::decode(logical_imm_raw(1, 0b00, 1, 1, 0, 1, 0)).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::AND);
        assert_eq!(
            insn.operands[2],
            Operand::Imm(Immediate::new(0x8000_0000_0000_0000u64 as i64))
        );

        // Rotate the single-bit mask the other way across the 64-bit boundary.
        let insn = Aarch64Decoder::decode(logical_imm_raw(1, 0b00, 1, 63, 0, 1, 0)).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::AND);
        assert_eq!(insn.operands[2], Operand::Imm(Immediate::new(2)));
    }

    #[test]
    fn test_logical_imm_mov_alias_respects_move_wide_preference() {
        for bytes in [
            [0xe0, 0x03, 0x40, 0xb2], // ORR X0, XZR, #1; MOVZ is preferred.
            [0xe0, 0x3f, 0x40, 0xb2], // ORR X0, XZR, #0xffff.
            [0xff, 0x3f, 0x40, 0xb2], // ORR SP, XZR, #0xffff.
            [0xe0, 0x3f, 0x00, 0x32], // ORR W0, WZR, #0xffff.
            [0xff, 0x3f, 0x00, 0x32], // ORR WSP, WZR, #0xffff.
        ] {
            let insn = decode_bytes(&bytes).unwrap();
            assert_eq!(insn.mnemonic, Mnemonic::ORR);
            assert_eq!(insn.operands.len(), 3);
        }

        for (bytes, dst) in [
            ([0xe0, 0x9f, 0x00, 0xb2], Register::x(0)),
            ([0xff, 0x9f, 0x00, 0xb2], Register::sp(true)),
            ([0xe0, 0x9f, 0x00, 0x32], Register::w(0)),
            ([0xff, 0x9f, 0x00, 0x32], Register::sp(false)),
        ] {
            let insn = decode_bytes(&bytes).unwrap();
            assert_eq!(insn.mnemonic, Mnemonic::MOV);
            assert_eq!(insn.operands.len(), 2);
            assert!(matches!(insn.operands.get(0), Some(Operand::Reg(reg)) if *reg == dst));
        }
    }

    #[test]
    fn test_logical_imm_reserved_all_ones_mask_is_undefined() {
        // N=1, imms=0x3f is the reserved all-ones logical-immediate encoding.
        // The decoder used to compute 1u64 << 64 here.
        let insn = Aarch64Decoder::decode(logical_imm_raw(1, 0b00, 1, 0, 0x3f, 1, 0)).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::UNDEFINED);

        let insn = Aarch64Decoder::decode(logical_imm_raw(1, 0b00, 1, 7, 0x3f, 1, 0)).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::UNDEFINED);
    }

    #[test]
    fn test_simd_two_reg_misc_distinct_mnemonics() {
        // Integer unary, vector FP, and narrowing forms retain their distinct
        // mnemonics. Each instruction uses V0 as destination and V1 as source.
        let cases: &[(u32, Mnemonic)] = &[
            (0x4E20_0820, Mnemonic::REV64),  // rev64 v0.16b, v1.16b
            (0x4E20_1820, Mnemonic::REV16),  // rev16 v0.16b, v1.16b
            (0x6E20_0820, Mnemonic::REV32),  // rev32 v0.16b, v1.16b
            (0x4EA0_4820, Mnemonic::CLS),    // cls   v0.4s,  v1.4s
            (0x6EA0_4820, Mnemonic::CLZ),    // clz   v0.4s,  v1.4s
            (0x6E20_5820, Mnemonic::VMVN),   // not   v0.16b, v1.16b
            (0x6E60_5820, Mnemonic::RBIT),   // rbit  v0.16b, v1.16b
            (0x6EA0_B820, Mnemonic::VNEG),   // neg   v0.4s,  v1.4s
            (0x4EA0_B820, Mnemonic::VABS),   // abs   v0.4s,  v1.4s
            (0x4EA0_F820, Mnemonic::FABS),   // fabs  v0.4s,  v1.4s
            (0x6EA0_F820, Mnemonic::FNEG),   // fneg  v0.4s,  v1.4s
            (0x6EA1_F820, Mnemonic::FSQRT),  // fsqrt v0.4s,  v1.4s
            (0x4E20_5820, Mnemonic::CNT),    // cnt   v0.16b, v1.16b
            (0x4EA1_4820, Mnemonic::VQMOVN), // sqxtn2 v0.4s, v1.2d
        ];
        for &(raw, expected) in cases {
            let insn = Aarch64Decoder::decode(raw).unwrap();
            assert_eq!(insn.mnemonic, expected, "raw={raw:#010x}");
        }
    }

    #[test]
    fn issue_48_decodes_scalar_fp_subclasses_by_subfields() {
        let frintn = decode_bytes(&[0x20, 0x40, 0x24, 0x1e]).unwrap();
        assert_eq!(frintn.mnemonic, Mnemonic::FRINTN);
        assert_eq!(frintn.operands.len(), 2);
        assert!(matches!(
            frintn.operands.first(),
            Some(Operand::FpReg(FpRegister {
                num: 0,
                size: FpRegSize::S
            }))
        ));
        assert!(matches!(
            frintn.operands.get(1),
            Some(Operand::FpReg(FpRegister {
                num: 1,
                size: FpRegSize::S
            }))
        ));

        let fcmp = decode_bytes(&[0x20, 0x20, 0x22, 0x1e]).unwrap();
        assert_eq!(fcmp.mnemonic, Mnemonic::FCMP);
        assert_eq!(fcmp.operands.len(), 2);
        assert!(matches!(
            fcmp.operands.first(),
            Some(Operand::FpReg(FpRegister {
                num: 1,
                size: FpRegSize::S
            }))
        ));
        assert!(matches!(
            fcmp.operands.get(1),
            Some(Operand::FpReg(FpRegister {
                num: 2,
                size: FpRegSize::S
            }))
        ));

        let fcmp_zero = decode_bytes(&[0x28, 0x20, 0x20, 0x1e]).unwrap();
        assert_eq!(fcmp_zero.mnemonic, Mnemonic::FCMP);
        assert_eq!(fcmp_zero.operands.len(), 1);
        assert!(matches!(
            fcmp_zero.operands.first(),
            Some(Operand::FpReg(FpRegister {
                num: 1,
                size: FpRegSize::S
            }))
        ));

        let fcsel = decode_bytes(&[0x20, 0x1c, 0x22, 0x1e]).unwrap();
        assert_eq!(fcsel.mnemonic, Mnemonic::FCSEL);
        assert_eq!(fcsel.operands.len(), 4);
        assert!(matches!(
            fcsel.operands.get(3),
            Some(Operand::Cond(Condition::NE))
        ));

        let fmov_imm = decode_bytes(&[0x00, 0x10, 0x2e, 0x1e]).unwrap();
        assert_eq!(fmov_imm.mnemonic, Mnemonic::UNKNOWN);

        let fccmp = decode_bytes(&[0x27, 0x14, 0x22, 0x1e]).unwrap();
        assert_eq!(fccmp.mnemonic, Mnemonic::UNKNOWN);
    }

    #[test]
    fn issue_48_rejects_reserved_scalar_fp_ptype() {
        let reserved_ptype = 0b10 << 22;

        let fadd_reserved = 0x1e22_2820 | reserved_ptype;
        let insn = Aarch64Decoder::decode(fadd_reserved).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::UNDEFINED);

        let fneg_reserved = 0x1e21_4020 | reserved_ptype;
        let insn = Aarch64Decoder::decode(fneg_reserved).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::UNDEFINED);

        let fcsel_reserved = 0x1e22_1c20 | reserved_ptype;
        let insn = Aarch64Decoder::decode(fcsel_reserved).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::UNDEFINED);

        let fmadd_reserved = 0x1f02_0c20 | reserved_ptype;
        let insn = Aarch64Decoder::decode(fmadd_reserved).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::UNDEFINED);
    }

    #[test]
    fn test_atomic_swp_decode() {
        // SWP X2, X0, [X1].
        let insn = Aarch64Decoder::decode(
            (0b11 << 30) | (0b111 << 27) | (1 << 21) | (2 << 16) | (1 << 15) | (1 << 5),
        )
        .unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::SWP);
        assert_eq!(insn.operands.len(), 3);

        // SWPAL W2, W0, [X1].
        let insn = Aarch64Decoder::decode(
            (0b111 << 27) | (1 << 23) | (1 << 22) | (1 << 21) | (2 << 16) | (1 << 15) | (1 << 5),
        )
        .unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::SWPAL);
        assert_eq!(insn.operands.len(), 3);
    }

    #[test]
    fn test_atomic_ldapr_decode() {
        fn ldapr(size: u32) -> u32 {
            (size << 30)
                | (0b111 << 27)
                | (1 << 23)
                | (1 << 21)
                | (31 << 16)
                | (1 << 15)
                | (0b100 << 12)
                | (1 << 5)
        }

        let cases = [
            (0b00, Mnemonic::LDAPRB, false),
            (0b01, Mnemonic::LDAPRH, false),
            (0b10, Mnemonic::LDAPR, false),
            (0b11, Mnemonic::LDAPR, true),
        ];
        for (size, mnemonic, is_64bit) in cases {
            let insn = Aarch64Decoder::decode(ldapr(size)).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            assert_eq!(insn.operands.len(), 2);
            assert!(
                matches!(insn.operands.get(0), Some(Operand::Reg(reg)) if reg.num == 0 && reg.is_64bit == is_64bit)
            );
            assert!(matches!(
                insn.operands.get(1),
                Some(Operand::Mem(mem)) if mem.base.num == 1 && !mem.base.is_sp
            ));
        }
    }

    #[test]
    fn test_atomic_cas_decode() {
        // CAS X2, X0, [X1].
        let insn = Aarch64Decoder::decode(
            (0b11 << 30)
                | (0b001000 << 24)
                | (1 << 23)
                | (1 << 21)
                | (2 << 16)
                | (0b11111 << 10)
                | (1 << 5),
        )
        .unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::CAS);
        assert_eq!(insn.operands.len(), 3);

        // CASAL W2, W0, [X1].
        let insn = Aarch64Decoder::decode(
            (0b001000 << 24)
                | (1 << 23)
                | (1 << 22)
                | (1 << 21)
                | (2 << 16)
                | (1 << 15)
                | (0b11111 << 10)
                | (1 << 5),
        )
        .unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::CASAL);
        assert_eq!(insn.operands.len(), 3);
    }

    #[test]
    fn test_atomic_casp_decode() {
        fn casp(sz: u32, l: u32, o0: u32) -> u32 {
            (sz << 30)
                | (0b001000 << 24)
                | (l << 22)
                | (1 << 21)
                | (2 << 16)
                | (o0 << 15)
                | (0b11111 << 10)
                | (1 << 5)
                | 4
        }

        let cases = [
            (0, 0, Mnemonic::CASP),
            (1, 0, Mnemonic::CASPA),
            (0, 1, Mnemonic::CASPL),
            (1, 1, Mnemonic::CASPAL),
        ];
        for sz in 0..2 {
            for (l, o0, mnemonic) in cases {
                let insn = Aarch64Decoder::decode(casp(sz, l, o0)).unwrap();
                assert_eq!(insn.mnemonic, mnemonic);
                assert_eq!(insn.operands.len(), 5);
                let is_64bit = sz == 1;
                assert!(
                    matches!(insn.operands.get(0), Some(Operand::Reg(reg)) if reg.num == 2 && reg.is_64bit == is_64bit)
                );
                assert!(
                    matches!(insn.operands.get(1), Some(Operand::Reg(reg)) if reg.num == 3 && reg.is_64bit == is_64bit)
                );
                assert!(
                    matches!(insn.operands.get(2), Some(Operand::Reg(reg)) if reg.num == 4 && reg.is_64bit == is_64bit)
                );
                assert!(
                    matches!(insn.operands.get(3), Some(Operand::Reg(reg)) if reg.num == 5 && reg.is_64bit == is_64bit)
                );
                assert!(matches!(
                    insn.operands.get(4),
                    Some(Operand::Mem(mem)) if mem.base.num == 1 && !mem.base.is_sp
                ));
            }
        }
    }

    #[test]
    fn test_store_exclusive_release_decode_operands() {
        // LDAXR X0, [X1].
        let insn = Aarch64Decoder::decode(
            (0b11 << 30)
                | (0b001000 << 24)
                | (1 << 22)
                | (0b11111 << 16)
                | (1 << 15)
                | (0b11111 << 10)
                | (1 << 5),
        )
        .unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::LDAXR);
        assert_eq!(insn.operands.len(), 2);

        // STLXR W2, X3, [X1].
        let insn = Aarch64Decoder::decode(
            (0b11 << 30)
                | (0b001000 << 24)
                | (2 << 16)
                | (1 << 15)
                | (0b11111 << 10)
                | (1 << 5)
                | 3,
        )
        .unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::STLXR);
        assert_eq!(insn.operands.len(), 3);

        // STLR X3, [X1] has no status operand.
        let insn = Aarch64Decoder::decode(
            (0b11 << 30)
                | (0b001000 << 24)
                | (1 << 23)
                | (0b11111 << 16)
                | (1 << 15)
                | (0b11111 << 10)
                | (1 << 5)
                | 3,
        )
        .unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::STLR);
        assert_eq!(insn.operands.len(), 2);
    }

    #[test]
    fn test_ordered_ldst_decode_rejects_widened_bucket() {
        let valid_stlrb = ordered_ldst_raw(0b00, false, 31, 31);

        let simd_structure = valid_stlrb | (1 << 26);
        let insn = Aarch64Decoder::decode(simd_structure).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::VSTR);

        let bit24_set = valid_stlrb | (1 << 24);
        let insn = Aarch64Decoder::decode(bit24_set).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::UNKNOWN);
    }

    #[test]
    fn test_ordered_ldst_decode_ignores_rs_and_rt2_fields() {
        let valid_ldar = Aarch64Decoder::decode(ordered_ldst_raw(0b11, true, 31, 31)).unwrap();
        assert_eq!(valid_ldar.mnemonic, Mnemonic::LDAR);

        let valid_stlr = Aarch64Decoder::decode(ordered_ldst_raw(0b11, false, 31, 31)).unwrap();
        assert_eq!(valid_stlr.mnemonic, Mnemonic::STLR);

        for (raw, mnemonic) in [
            (ordered_ldst_raw(0b00, true, 0, 31), Mnemonic::LDARB),
            (ordered_ldst_raw(0b01, true, 31, 0), Mnemonic::LDARH),
            (ordered_ldst_raw(0b11, true, 0, 0), Mnemonic::LDAR),
            (ordered_ldst_raw(0b00, false, 0, 31), Mnemonic::STLRB),
            (ordered_ldst_raw(0b01, false, 31, 0), Mnemonic::STLRH),
            (ordered_ldst_raw(0b11, false, 0, 0), Mnemonic::STLR),
        ] {
            let insn = Aarch64Decoder::decode(raw).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            assert_eq!(insn.operands.len(), 2);
        }
    }

    #[test]
    fn test_loregion_ordered_ldst_decode() {
        fn loregion_raw(size: u32, load: bool, rs: u32, rt2: u32) -> u32 {
            let l = if load { 1 } else { 0 };
            (size << 30)
                | (0b001000 << 24)
                | (1 << 23)
                | (l << 22)
                | (rs << 16)
                | (rt2 << 10)
                | (1 << 5)
                | 3
        }

        let cases = [
            (0b00, true, Mnemonic::LDLARB, false),
            (0b01, true, Mnemonic::LDLARH, false),
            (0b10, true, Mnemonic::LDLAR, false),
            (0b11, true, Mnemonic::LDLAR, true),
            (0b00, false, Mnemonic::STLLRB, false),
            (0b01, false, Mnemonic::STLLRH, false),
            (0b10, false, Mnemonic::STLLR, false),
            (0b11, false, Mnemonic::STLLR, true),
        ];

        for (size, load, mnemonic, is_64bit) in cases {
            let insn = Aarch64Decoder::decode(loregion_raw(size, load, 31, 31)).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            assert_eq!(insn.operands.len(), 2);
            assert!(
                matches!(insn.operands.get(0), Some(Operand::Reg(reg)) if reg.num == 3 && reg.is_64bit == is_64bit)
            );
            assert!(matches!(
                insn.operands.get(1),
                Some(Operand::Mem(mem)) if mem.base.num == 1 && !mem.base.is_sp
            ));
        }

        for (raw, mnemonic) in [
            (loregion_raw(0b00, true, 0, 31), Mnemonic::LDLARB),
            (loregion_raw(0b01, true, 31, 0), Mnemonic::LDLARH),
            (loregion_raw(0b11, true, 0, 0), Mnemonic::LDLAR),
            (loregion_raw(0b00, false, 0, 31), Mnemonic::STLLRB),
            (loregion_raw(0b01, false, 31, 0), Mnemonic::STLLRH),
            (loregion_raw(0b11, false, 0, 0), Mnemonic::STLLR),
        ] {
            let insn = Aarch64Decoder::decode(raw).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            assert_eq!(insn.operands.len(), 2);
        }
    }

    #[test]
    fn test_clrex_decode() {
        // CLREX: d5033f5f.
        let insn = decode_bytes(&[0x5f, 0x3f, 0x03, 0xd5]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::CLREX);
        assert_eq!(insn.operands.len(), 1);
    }

    #[test]
    fn test_sb_decode() {
        // SB: d50330ff.
        let insn = decode_bytes(&[0xff, 0x30, 0x03, 0xd5]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::SB);
        assert_eq!(insn.mnemonic.as_str(), "sb");
        assert_eq!(insn.operands.len(), 1);
    }

    #[test]
    fn test_sub_imm() {
        // SUB X0, X1, #0x10: d1004020
        let insn = decode_bytes(&[0x20, 0x40, 0x00, 0xd1]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::SUB);
    }

    #[test]
    fn test_add_sub_imm_tags() {
        fn addsub_tags_raw(sf: u32, op: u32, s: u32, o2: u32) -> u32 {
            (sf << 31) | (op << 30) | (s << 29) | (0b100011 << 23) | (o2 << 22) | 0x0001_0020
        }

        // ADDG X0, X1, #0x10, #0: 91810020
        let insn = decode_bytes(&[0x20, 0x00, 0x81, 0x91]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::ADDG);
        assert_eq!(insn.operands.len(), 4);
        if let Some(Operand::Imm(offset)) = insn.operands.get(2) {
            assert_eq!(offset.effective_value(), 0x10);
        } else {
            panic!("Expected ADDG offset immediate");
        }

        // SUBG X0, X1, #0x10, #0: d1810020
        let insn = decode_bytes(&[0x20, 0x00, 0x81, 0xd1]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::SUBG);

        for raw in [
            addsub_tags_raw(0, 0, 0, 0),
            addsub_tags_raw(1, 0, 1, 0),
            addsub_tags_raw(1, 0, 0, 1),
            addsub_tags_raw(0, 1, 0, 0),
            addsub_tags_raw(1, 1, 1, 0),
            addsub_tags_raw(1, 1, 0, 1),
        ] {
            let insn = Aarch64Decoder::decode(raw).unwrap();
            assert_eq!(insn.mnemonic, Mnemonic::UNDEFINED, "raw={raw:#010x}");
        }
    }

    #[test]
    fn test_mte_dp2_register_31_decode() {
        fn mte_dp2(s: u32, opcode: u32, rn: u32, rm: u32, rd: u32) -> u32 {
            (1 << 31)
                | ((s & 1) << 29)
                | (0b0011010110 << 21)
                | ((rm & 0x1f) << 16)
                | ((opcode & 0x3f) << 10)
                | ((rn & 0x1f) << 5)
                | (rd & 0x1f)
        }

        let subp = Aarch64Decoder::decode(mte_dp2(0, 0b000000, 31, 31, 0)).unwrap();
        assert_eq!(subp.mnemonic, Mnemonic::SUBP);
        assert!(!subp.sets_flags);
        assert!(
            matches!(subp.operands.get(0), Some(Operand::Reg(reg)) if reg.num == 0 && !reg.is_sp)
        );
        assert!(
            matches!(subp.operands.get(1), Some(Operand::Reg(reg)) if reg.num == 31 && reg.is_sp)
        );
        assert!(
            matches!(subp.operands.get(2), Some(Operand::Reg(reg)) if reg.num == 31 && reg.is_sp)
        );

        let subps = Aarch64Decoder::decode(mte_dp2(1, 0b000000, 1, 31, 0)).unwrap();
        assert_eq!(subps.mnemonic, Mnemonic::SUBPS);
        assert!(subps.sets_flags);
        assert!(
            matches!(subps.operands.get(1), Some(Operand::Reg(reg)) if reg.num == 1 && !reg.is_sp)
        );
        assert!(
            matches!(subps.operands.get(2), Some(Operand::Reg(reg)) if reg.num == 31 && reg.is_sp)
        );

        let invalid_s_bit = Aarch64Decoder::decode(mte_dp2(1, 0b001000, 1, 2, 0)).unwrap();
        assert_eq!(invalid_s_bit.mnemonic, Mnemonic::UNDEFINED);

        let irg = Aarch64Decoder::decode(mte_dp2(0, 0b000100, 31, 2, 31)).unwrap();
        assert_eq!(irg.mnemonic, Mnemonic::IRG);
        assert!(
            matches!(irg.operands.get(0), Some(Operand::Reg(reg)) if reg.num == 31 && reg.is_sp)
        );
        assert!(
            matches!(irg.operands.get(1), Some(Operand::Reg(reg)) if reg.num == 31 && reg.is_sp)
        );
        assert!(
            matches!(irg.operands.get(2), Some(Operand::Reg(reg)) if reg.num == 2 && !reg.is_sp)
        );

        let gmi = Aarch64Decoder::decode(mte_dp2(0, 0b000101, 31, 31, 0)).unwrap();
        assert_eq!(gmi.mnemonic, Mnemonic::GMI);
        assert!(
            matches!(gmi.operands.get(0), Some(Operand::Reg(reg)) if reg.num == 0 && !reg.is_sp)
        );
        assert!(
            matches!(gmi.operands.get(1), Some(Operand::Reg(reg)) if reg.num == 31 && reg.is_sp)
        );
        assert!(
            matches!(gmi.operands.get(2), Some(Operand::Reg(reg)) if reg.num == 31 && !reg.is_sp)
        );
    }

    #[test]
    fn test_mte_tag_memory_decode() {
        fn tag_mem(opc: u32, imm9: i32, op2: u32, rn: u32, rt: u32) -> u32 {
            (0xD9 << 24)
                | ((opc & 0x3) << 22)
                | (1 << 21)
                | (((imm9 as u32) & 0x1ff) << 12)
                | ((op2 & 0x3) << 10)
                | ((rn & 0x1f) << 5)
                | (rt & 0x1f)
        }

        let ldg = Aarch64Decoder::decode(tag_mem(0b01, -1, 0b00, 31, 31)).unwrap();
        assert_eq!(ldg.mnemonic, Mnemonic::LDG);
        assert!(
            matches!(ldg.operands.get(0), Some(Operand::Reg(reg)) if reg.num == 31 && !reg.is_sp)
        );
        assert!(matches!(
            ldg.operands.get(1),
            Some(Operand::Mem(mem))
                if mem.base.num == 31
                    && mem.base.is_sp
                    && mem.mode == AddressingMode::Offset
                    && mem.offset == MemOffset::Imm(-16)
        ));

        let cases = [
            (0b00, 0b01, Mnemonic::STG, AddressingMode::PostIndex),
            (0b01, 0b10, Mnemonic::STZG, AddressingMode::Offset),
            (0b10, 0b11, Mnemonic::ST2G, AddressingMode::PreIndex),
            (0b11, 0b10, Mnemonic::STZ2G, AddressingMode::Offset),
        ];
        for (opc, op2, mnemonic, mode) in cases {
            let insn = Aarch64Decoder::decode(tag_mem(opc, -1, op2, 31, 31)).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            assert!(
                matches!(insn.operands.get(0), Some(Operand::Reg(reg)) if reg.num == 31 && !reg.is_sp)
            );
            assert!(matches!(
                insn.operands.get(1),
                Some(Operand::Mem(mem))
                    if mem.base.num == 31
                        && mem.base.is_sp
                        && mem.mode == mode
                        && mem.offset == MemOffset::Imm(-16)
            ));
        }

        let unnamed_bulk = Aarch64Decoder::decode(tag_mem(0b00, -1, 0b00, 1, 0)).unwrap();
        assert_eq!(unnamed_bulk.mnemonic, Mnemonic::UNKNOWN);
    }

    #[test]
    fn test_pacga_register_31_decode() {
        fn pacga(rn: u32, rm: u32, rd: u32) -> u32 {
            (1 << 31)
                | (0b0011010110 << 21)
                | ((rm & 0x1f) << 16)
                | (0b001100 << 10)
                | ((rn & 0x1f) << 5)
                | (rd & 0x1f)
        }

        let dst_src_xzr = Aarch64Decoder::decode(pacga(31, 2, 31)).unwrap();
        assert_eq!(dst_src_xzr.mnemonic, Mnemonic::PACGA);
        assert!(
            matches!(dst_src_xzr.operands.get(0), Some(Operand::Reg(reg)) if reg.num == 31 && !reg.is_sp)
        );
        assert!(
            matches!(dst_src_xzr.operands.get(1), Some(Operand::Reg(reg)) if reg.num == 31 && !reg.is_sp)
        );
        assert!(
            matches!(dst_src_xzr.operands.get(2), Some(Operand::Reg(reg)) if reg.num == 2 && !reg.is_sp)
        );

        let sp_modifier = Aarch64Decoder::decode(pacga(1, 31, 0)).unwrap();
        assert_eq!(sp_modifier.mnemonic, Mnemonic::PACGA);
        assert!(
            matches!(sp_modifier.operands.get(0), Some(Operand::Reg(reg)) if reg.num == 0 && !reg.is_sp)
        );
        assert!(
            matches!(sp_modifier.operands.get(1), Some(Operand::Reg(reg)) if reg.num == 1 && !reg.is_sp)
        );
        assert!(
            matches!(sp_modifier.operands.get(2), Some(Operand::Reg(reg)) if reg.num == 31 && reg.is_sp)
        );
    }

    #[test]
    fn test_pauth_dp1_decode() {
        fn pauth_dp1(opcode: u32, rn: u32, rd: u32) -> u32 {
            (1 << 31)
                | (0b1011010110 << 21)
                | (0b00001 << 16)
                | ((opcode & 0x3f) << 10)
                | ((rn & 0x1f) << 5)
                | (rd & 0x1f)
        }

        let modifier_forms = [
            (0b000000, Mnemonic::PACIA),
            (0b000001, Mnemonic::PACIB),
            (0b000010, Mnemonic::PACDA),
            (0b000011, Mnemonic::PACDB),
            (0b000100, Mnemonic::AUTIA),
            (0b000101, Mnemonic::AUTIB),
            (0b000110, Mnemonic::AUTDA),
            (0b000111, Mnemonic::AUTDB),
        ];
        for (opcode, mnemonic) in modifier_forms {
            let insn = Aarch64Decoder::decode(pauth_dp1(opcode, 31, 0)).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            assert_eq!(insn.operands.len(), 2);
            assert!(
                matches!(insn.operands.get(0), Some(Operand::Reg(reg)) if reg.num == 0 && !reg.is_sp)
            );
            assert!(
                matches!(insn.operands.get(1), Some(Operand::Reg(reg)) if reg.num == 31 && reg.is_sp)
            );
        }

        let zero_modifier_forms = [
            (0b001000, Mnemonic::PACIZA),
            (0b001001, Mnemonic::PACIZB),
            (0b001010, Mnemonic::PACDZA),
            (0b001011, Mnemonic::PACDZB),
            (0b001100, Mnemonic::AUTIZA),
            (0b001101, Mnemonic::AUTIZB),
            (0b001110, Mnemonic::AUTDZA),
            (0b001111, Mnemonic::AUTDZB),
            (0b010000, Mnemonic::XPACI),
            (0b010001, Mnemonic::XPACD),
        ];
        for (opcode, mnemonic) in zero_modifier_forms {
            let insn = Aarch64Decoder::decode(pauth_dp1(opcode, 31, 31)).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            assert_eq!(insn.operands.len(), 1);
            assert!(
                matches!(insn.operands.get(0), Some(Operand::Reg(reg)) if reg.num == 31 && !reg.is_sp)
            );

            let invalid_rn = Aarch64Decoder::decode(pauth_dp1(opcode, 1, 0)).unwrap();
            assert_eq!(invalid_rn.mnemonic, Mnemonic::UNDEFINED);
        }
    }

    #[test]
    fn test_cmp_imm() {
        // CMP X0, #0 -> SUBS XZR, X0, #0: f100001f
        let insn = decode_bytes(&[0x1f, 0x00, 0x00, 0xf1]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::CMP);
        assert!(insn.sets_flags);
    }

    #[test]
    fn test_bitfield_extend_aliases_use_two_register_operands() {
        for (bytes, mnemonic, dst, src) in [
            (
                [0x20, 0x1c, 0x40, 0x93],
                Mnemonic::SXTB,
                Register::x(0),
                Register::w(1),
            ),
            (
                [0x20, 0x3c, 0x40, 0x93],
                Mnemonic::SXTH,
                Register::x(0),
                Register::w(1),
            ),
            (
                [0x20, 0x1c, 0x00, 0x13],
                Mnemonic::SXTB,
                Register::w(0),
                Register::w(1),
            ),
            (
                [0x20, 0x3c, 0x00, 0x13],
                Mnemonic::SXTH,
                Register::w(0),
                Register::w(1),
            ),
            (
                [0x20, 0x7c, 0x40, 0x93],
                Mnemonic::SXTW,
                Register::x(0),
                Register::w(1),
            ),
            (
                [0x20, 0x1c, 0x00, 0x53],
                Mnemonic::UXTB,
                Register::w(0),
                Register::w(1),
            ),
            (
                [0x20, 0x3c, 0x00, 0x53],
                Mnemonic::UXTH,
                Register::w(0),
                Register::w(1),
            ),
        ] {
            let insn = decode_bytes(&bytes).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            assert_eq!(insn.operands.len(), 2);
            assert!(matches!(insn.operands.get(0), Some(Operand::Reg(reg)) if *reg == dst));
            assert!(matches!(insn.operands.get(1), Some(Operand::Reg(reg)) if *reg == src));
        }
    }

    #[test]
    fn test_b() {
        // B #0x100: 14000040
        let insn = decode_bytes(&[0x40, 0x00, 0x00, 0x14]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::B);
        if let Some(Operand::Label(offset)) = insn.operands.first() {
            assert_eq!(*offset, 0x100);
        } else {
            panic!("Expected label operand");
        }
    }

    #[test]
    fn test_bl() {
        // BL #0x100: 94000040
        let insn = decode_bytes(&[0x40, 0x00, 0x00, 0x94]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::BL);
    }

    #[test]
    fn test_cbz() {
        // CBZ X0, #0x10: b4000080
        let insn = decode_bytes(&[0x80, 0x00, 0x00, 0xb4]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::CBZ);
    }

    #[test]
    fn test_cbnz() {
        // CBNZ W0, #0x10: 35000080
        let insn = decode_bytes(&[0x80, 0x00, 0x00, 0x35]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::CBNZ);
    }

    #[test]
    fn test_ldr_imm() {
        // LDR X0, [X1]: f9400020
        let insn = decode_bytes(&[0x20, 0x00, 0x40, 0xf9]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::LDR);
        assert_eq!(insn.operands.len(), 2);
    }

    #[test]
    fn test_str_imm() {
        // STR X0, [X1]: f9000020
        let insn = decode_bytes(&[0x20, 0x00, 0x00, 0xf9]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::STR);
    }

    #[test]
    fn test_ldp() {
        // LDP X0, X1, [SP]: a9400be0
        let insn = decode_bytes(&[0xe0, 0x07, 0x40, 0xa9]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::LDP);
        assert_eq!(insn.operands.len(), 3);
    }

    #[test]
    fn test_stp() {
        // STP X29, X30, [SP, #-16]!: a9bf7bfd
        let insn = decode_bytes(&[0xfd, 0x7b, 0xbf, 0xa9]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::STP);
    }

    #[test]
    fn test_stgp_decode() {
        fn pair(opc: u32, mode: u32, l: u32, imm7: i32, rt2: u32, rn: u32, rt: u32) -> u32 {
            (opc << 30)
                | (0b101 << 27)
                | (mode << 23)
                | (l << 22)
                | (((imm7 as u32) & 0x7f) << 15)
                | ((rt2 & 0x1f) << 10)
                | ((rn & 0x1f) << 5)
                | (rt & 0x1f)
        }

        let cases = [
            (0b01, AddressingMode::PostIndex),
            (0b10, AddressingMode::Offset),
            (0b11, AddressingMode::PreIndex),
        ];
        for (mode_bits, mode) in cases {
            let insn = Aarch64Decoder::decode(pair(0b01, mode_bits, 0, -1, 30, 31, 31)).unwrap();
            assert_eq!(insn.mnemonic, Mnemonic::STGP);
            assert!(
                matches!(insn.operands.get(0), Some(Operand::Reg(reg)) if reg.num == 31 && !reg.is_sp)
            );
            assert!(
                matches!(insn.operands.get(1), Some(Operand::Reg(reg)) if reg.num == 30 && !reg.is_sp)
            );
            assert!(matches!(
                insn.operands.get(2),
                Some(Operand::Mem(mem))
                    if mem.base.num == 31
                        && mem.base.is_sp
                        && mem.mode == mode
                        && mem.offset == MemOffset::Imm(-16)
            ));
        }

        let no_allocate = Aarch64Decoder::decode(pair(0b01, 0b00, 0, 0, 1, 2, 0)).unwrap();
        assert_eq!(no_allocate.mnemonic, Mnemonic::UNDEFINED);
    }

    #[test]
    fn test_lrcpc3_pair_decode() {
        fn pair(mode: u32, l: u32, imm7: i32, rt2: u32, rn: u32, rt: u32) -> u32 {
            (0b11 << 30)
                | (0b101 << 27)
                | (mode << 23)
                | (l << 22)
                | (((imm7 as u32) & 0x7f) << 15)
                | ((rt2 & 0x1f) << 10)
                | ((rn & 0x1f) << 5)
                | (rt & 0x1f)
        }

        let cases = [
            (0b00, 1, Mnemonic::LDTNP, AddressingMode::Offset),
            (0b00, 0, Mnemonic::STTNP, AddressingMode::Offset),
            (0b10, 1, Mnemonic::LDTP, AddressingMode::Offset),
            (0b01, 0, Mnemonic::STTP, AddressingMode::PostIndex),
            (0b11, 1, Mnemonic::LDTP, AddressingMode::PreIndex),
        ];

        for (mode_bits, l, mnemonic, mode) in cases {
            let insn = Aarch64Decoder::decode(pair(mode_bits, l, -1, 30, 31, 29)).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            assert!(
                matches!(insn.operands.get(0), Some(Operand::Reg(reg)) if reg.num == 29 && reg.is_64bit && !reg.is_sp)
            );
            assert!(
                matches!(insn.operands.get(1), Some(Operand::Reg(reg)) if reg.num == 30 && reg.is_64bit && !reg.is_sp)
            );
            assert!(matches!(
                insn.operands.get(2),
                Some(Operand::Mem(mem))
                    if mem.base.num == 31
                        && mem.base.is_sp
                        && mem.mode == mode
                        && mem.offset == MemOffset::Imm(-8)
            ));
        }
    }

    #[test]
    fn test_ordered_unscaled_decode() {
        fn ordered(size: u32, opc: u32, imm9: i32, rn: u32, rt: u32) -> u32 {
            (size << 30)
                | (0b011001 << 24)
                | (opc << 22)
                | (((imm9 as u32) & 0x1ff) << 12)
                | ((rn & 0x1f) << 5)
                | (rt & 0x1f)
        }

        let cases = [
            (0b00, 0b00, Mnemonic::STLURB, false),
            (0b01, 0b00, Mnemonic::STLURH, false),
            (0b10, 0b00, Mnemonic::STLUR, false),
            (0b11, 0b00, Mnemonic::STLUR, true),
            (0b00, 0b01, Mnemonic::LDAPURB, false),
            (0b01, 0b01, Mnemonic::LDAPURH, false),
            (0b10, 0b01, Mnemonic::LDAPUR, false),
            (0b11, 0b01, Mnemonic::LDAPUR, true),
            (0b00, 0b10, Mnemonic::LDAPURSB, true),
            (0b01, 0b10, Mnemonic::LDAPURSH, true),
            (0b10, 0b10, Mnemonic::LDAPURSW, true),
            (0b00, 0b11, Mnemonic::LDAPURSB, false),
            (0b01, 0b11, Mnemonic::LDAPURSH, false),
        ];

        for (size, opc, mnemonic, is_64bit) in cases {
            let insn = Aarch64Decoder::decode(ordered(size, opc, -16, 31, 29)).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            assert!(
                matches!(insn.operands.get(0), Some(Operand::Reg(reg)) if reg.num == 29 && reg.is_64bit == is_64bit && !reg.is_sp)
            );
            assert!(matches!(
                insn.operands.get(1),
                Some(Operand::Mem(mem))
                    if mem.base.num == 31
                        && mem.base.is_sp
                        && mem.mode == AddressingMode::Offset
                        && mem.offset == MemOffset::Imm(-16)
            ));
        }

        let invalid_signed_x = Aarch64Decoder::decode(ordered(0b11, 0b10, 0, 1, 0)).unwrap();
        assert_eq!(invalid_signed_x.mnemonic, Mnemonic::UNDEFINED);
        let invalid_signed_w = Aarch64Decoder::decode(ordered(0b10, 0b11, 0, 1, 0)).unwrap();
        assert_eq!(invalid_signed_w.mnemonic, Mnemonic::UNDEFINED);
    }

    #[test]
    fn test_unprivileged_load_store_decode() {
        fn unprivileged(size: u32, opc: u32, imm9: i32, rn: u32, rt: u32) -> u32 {
            (size << 30)
                | (0b111 << 27)
                | (opc << 22)
                | (((imm9 as u32) & 0x1ff) << 12)
                | (0b10 << 10)
                | ((rn & 0x1f) << 5)
                | (rt & 0x1f)
        }

        let cases = [
            (0b00, 0b00, Mnemonic::STTRB, false),
            (0b01, 0b00, Mnemonic::STTRH, false),
            (0b10, 0b00, Mnemonic::STTR, false),
            (0b11, 0b00, Mnemonic::STTR, true),
            (0b00, 0b01, Mnemonic::LDTRB, false),
            (0b01, 0b01, Mnemonic::LDTRH, false),
            (0b10, 0b01, Mnemonic::LDTR, false),
            (0b11, 0b01, Mnemonic::LDTR, true),
            (0b00, 0b10, Mnemonic::LDTRSB, true),
            (0b01, 0b10, Mnemonic::LDTRSH, true),
            (0b10, 0b10, Mnemonic::LDTRSW, true),
            (0b00, 0b11, Mnemonic::LDTRSB, false),
            (0b01, 0b11, Mnemonic::LDTRSH, false),
        ];

        for (size, opc, mnemonic, is_64bit) in cases {
            let insn = Aarch64Decoder::decode(unprivileged(size, opc, -16, 31, 29)).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            assert!(
                matches!(insn.operands.get(0), Some(Operand::Reg(reg)) if reg.num == 29 && reg.is_64bit == is_64bit && !reg.is_sp)
            );
            assert!(matches!(
                insn.operands.get(1),
                Some(Operand::Mem(mem))
                    if mem.base.num == 31
                        && mem.base.is_sp
                        && mem.mode == AddressingMode::Offset
                        && mem.offset == MemOffset::Imm(-16)
            ));
        }

        let invalid_signed_x = Aarch64Decoder::decode(unprivileged(0b11, 0b10, 0, 1, 0)).unwrap();
        assert_eq!(invalid_signed_x.mnemonic, Mnemonic::UNDEFINED);
        let invalid_signed_w = Aarch64Decoder::decode(unprivileged(0b10, 0b11, 0, 1, 0)).unwrap();
        assert_eq!(invalid_signed_w.mnemonic, Mnemonic::UNDEFINED);
    }

    #[test]
    fn test_svc() {
        // SVC #0: d4000001
        let insn = decode_bytes(&[0x01, 0x00, 0x00, 0xd4]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::SVC);
    }

    #[test]
    fn test_brk() {
        // BRK #0: d4200000
        let insn = decode_bytes(&[0x00, 0x00, 0x20, 0xd4]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::BRK);
    }

    #[test]
    fn test_and_shifted_reg() {
        // AND X0, X1, X2: 8a020020
        let insn = decode_bytes(&[0x20, 0x00, 0x02, 0x8a]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::AND);
    }

    #[test]
    fn test_orr_shifted_reg() {
        // ORR X0, X1, X2: aa020020
        let insn = decode_bytes(&[0x20, 0x00, 0x02, 0xaa]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::ORR);
    }

    #[test]
    fn test_mov_reg() {
        // MOV X0, X1 -> ORR X0, XZR, X1: aa0103e0
        let insn = decode_bytes(&[0xe0, 0x03, 0x01, 0xaa]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::MOV);
    }

    #[test]
    fn test_logical_shifted_mov_alias_requires_lsl_zero() {
        let mov = decode_bytes(&[0xe0, 0x03, 0x01, 0xaa]).unwrap();
        assert_eq!(mov.mnemonic, Mnemonic::MOV);
        assert_eq!(mov.operands.len(), 2);

        for bytes in [
            [0xe0, 0x03, 0x41, 0xaa], // ORR X0, XZR, X1, LSR #0
            [0xe0, 0x03, 0x81, 0xaa], // ORR X0, XZR, X1, ASR #0
        ] {
            let insn = decode_bytes(&bytes).unwrap();
            assert_eq!(insn.mnemonic, Mnemonic::ORR);
            assert_eq!(insn.operands.len(), 3);
            assert!(
                matches!(insn.operands.get(1), Some(Operand::Reg(reg)) if *reg == Register::zr(true))
            );
            assert!(
                matches!(insn.operands.get(2), Some(Operand::ShiftedReg(shifted)) if shifted.immediate_amount() == Some(0))
            );
        }
    }

    #[test]
    fn test_bfm_xzr_extract_low_keeps_bfxil_alias() {
        let insn = decode_bytes(&[0xe0, 0x07, 0x41, 0xb3]).unwrap();

        assert_eq!(insn.mnemonic, Mnemonic::BFXIL);
        assert!(matches!(insn.operands.get(0), Some(Operand::Reg(reg)) if *reg == Register::x(0)));
        assert!(
            matches!(insn.operands.get(1), Some(Operand::Reg(reg)) if *reg == Register::zr(true))
        );
        assert!(matches!(insn.operands.get(2), Some(Operand::Imm(imm)) if imm.value == 1));
        assert!(matches!(insn.operands.get(3), Some(Operand::Imm(imm)) if imm.value == 1));
    }

    #[test]
    fn test_madd() {
        // MADD X0, X1, X2, X3: 9b020c20
        let insn = decode_bytes(&[0x20, 0x0c, 0x02, 0x9b]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::MADD);
    }

    #[test]
    fn test_mul() {
        // MUL X0, X1, X2 -> MADD X0, X1, X2, XZR: 9b027c20
        let insn = decode_bytes(&[0x20, 0x7c, 0x02, 0x9b]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::MUL);
    }

    #[test]
    fn test_long_multiply_negative_aliases() {
        for (bytes, mnemonic) in [
            ([0x20, 0xfc, 0x22, 0x9b], Mnemonic::SMNEGL),
            ([0x20, 0xfc, 0xa2, 0x9b], Mnemonic::UMNEGL),
        ] {
            let insn = decode_bytes(&bytes).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            assert_eq!(insn.operands.len(), 3);
            assert!(
                matches!(insn.operands.get(0), Some(Operand::Reg(reg)) if *reg == Register::x(0))
            );
            assert!(
                matches!(insn.operands.get(1), Some(Operand::Reg(reg)) if *reg == Register::w(1))
            );
            assert!(
                matches!(insn.operands.get(2), Some(Operand::Reg(reg)) if *reg == Register::w(2))
            );
        }
    }

    #[test]
    fn test_high_multiply_omits_ra_operand() {
        fn dp3(sf: u32, op31: u32, o0: u32, ra: u32) -> u32 {
            (sf << 31)
                | (0b11011 << 24)
                | (op31 << 21)
                | (2 << 16)
                | (o0 << 15)
                | ((ra & 0x1f) << 10)
                | (1 << 5)
        }

        for (mnemonic, op31, o0) in [(Mnemonic::SMULH, 0b010, 0), (Mnemonic::UMULH, 0b110, 0)] {
            for ra in [3, 31] {
                let insn = Aarch64Decoder::decode(dp3(1, op31, o0, ra)).unwrap();
                assert_eq!(insn.mnemonic, mnemonic);
                assert_eq!(insn.operands.len(), 3, "ra={ra}");
            }
        }
    }

    #[test]
    fn test_udiv() {
        // UDIV X0, X1, X2: 9ac20820
        let insn = decode_bytes(&[0x20, 0x08, 0xc2, 0x9a]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::UDIV);
    }

    #[test]
    fn test_sdiv() {
        // SDIV X0, X1, X2: 9ac20c20
        let insn = decode_bytes(&[0x20, 0x0c, 0xc2, 0x9a]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::SDIV);
    }

    #[test]
    fn test_csel() {
        // CSEL X0, X1, X2, EQ: 9a820020
        let insn = decode_bytes(&[0x20, 0x00, 0x82, 0x9a]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::CSEL);
    }

    #[test]
    fn test_csinv_keeps_source_operands() {
        // CSINV X0, X1, X2, NE: da821020
        let insn = decode_bytes(&[0x20, 0x10, 0x82, 0xda]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::CSINV);
        assert_eq!(insn.operands.len(), 4);
        assert!(matches!(insn.operands.get(1), Some(Operand::Reg(reg)) if reg.num == 1));
        assert!(matches!(insn.operands.get(2), Some(Operand::Reg(reg)) if reg.num == 2));
        assert!(matches!(
            insn.operands.get(3),
            Some(Operand::Cond(Condition::NE))
        ));
    }

    #[test]
    fn test_csetm_omits_source_operands() {
        // CSETM X0, EQ (CSINV X0, XZR, XZR, NE): da9f13e0
        let insn = decode_bytes(&[0xe0, 0x13, 0x9f, 0xda]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::CSETM);
        assert_eq!(insn.operands.len(), 2);
        assert!(matches!(
            insn.operands.get(1),
            Some(Operand::Cond(Condition::EQ))
        ));
    }

    #[test]
    fn test_cond_select_aliases_invert_condition_operand() {
        fn csel(sf: u32, op: u32, op2: u32, rn: u32, rm: u32, cond: u32) -> u32 {
            (sf << 31)
                | (op << 30)
                | (0b11010100 << 21)
                | ((rm & 0x1f) << 16)
                | ((cond & 0xf) << 12)
                | ((op2 & 0x3) << 10)
                | ((rn & 0x1f) << 5)
        }

        for (mnemonic, raw, cond_idx) in [
            (Mnemonic::CSET, csel(1, 0, 0b01, 31, 31, 1), 1),
            (Mnemonic::CSETM, csel(1, 1, 0b00, 31, 31, 1), 1),
            (Mnemonic::CINC, csel(1, 0, 0b01, 1, 1, 1), 2),
            (Mnemonic::CINV, csel(1, 1, 0b00, 1, 1, 1), 2),
            (Mnemonic::CNEG, csel(1, 1, 0b01, 1, 1, 1), 2),
        ] {
            let insn = Aarch64Decoder::decode(raw).unwrap();
            assert_eq!(insn.mnemonic, mnemonic);
            assert!(matches!(
                insn.operands.get(cond_idx),
                Some(Operand::Cond(Condition::EQ))
            ));
        }

        let insn = Aarch64Decoder::decode(csel(1, 0, 0b00, 1, 2, 1)).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::CSEL);
        assert!(matches!(
            insn.operands.get(3),
            Some(Operand::Cond(Condition::NE))
        ));
    }

    #[test]
    fn test_wfxt_decode() {
        let wfet = decode_bytes(&[0x00, 0x10, 0x03, 0xd5]).unwrap();
        assert_eq!(wfet.mnemonic, Mnemonic::WFET);
        assert!(matches!(
            wfet.operands.first(),
            Some(Operand::Reg(reg)) if reg.num == 0 && reg.is_64bit
        ));

        let wfit = decode_bytes(&[0x21, 0x10, 0x03, 0xd5]).unwrap();
        assert_eq!(wfit.mnemonic, Mnemonic::WFIT);
        assert!(matches!(
            wfit.operands.first(),
            Some(Operand::Reg(reg)) if reg.num == 1 && reg.is_64bit
        ));

        let wfet_xzr = decode_bytes(&[0x1f, 0x10, 0x03, 0xd5]).unwrap();
        assert_eq!(wfet_xzr.mnemonic, Mnemonic::WFET);
        assert!(matches!(
            wfet_xzr.operands.first(),
            Some(Operand::Reg(reg)) if reg.num == 31 && !reg.is_sp
        ));
    }

    #[test]
    fn test_dgh_hint_decode() {
        let insn = decode_bytes(&[0xdf, 0x20, 0x03, 0xd5]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::DGH);
        assert!(insn.operands.is_empty());
    }

    #[test]
    fn test_adc() {
        // ADC X0, X1, X2: 9a020020
        let insn = decode_bytes(&[0x20, 0x00, 0x02, 0x9a]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::ADC);
    }

    #[test]
    fn test_sbc_xzr_source_decodes_ngc_aliases() {
        fn addsub_carry(sf: u32, op: u32, s: u32, rn: u32) -> u32 {
            (sf << 31)
                | (op << 30)
                | (s << 29)
                | (0b11010000 << 21)
                | (2 << 16)
                | ((rn & 0x1f) << 5)
        }

        let sbc = Aarch64Decoder::decode(addsub_carry(1, 1, 0, 31)).unwrap();
        assert_eq!(sbc.mnemonic, Mnemonic::NGC);
        assert_eq!(sbc.operands.len(), 2);
        assert!(matches!(sbc.operands.get(0), Some(Operand::Reg(reg)) if *reg == Register::x(0)));
        assert!(matches!(sbc.operands.get(1), Some(Operand::Reg(reg)) if *reg == Register::x(2)));

        let sbcs = Aarch64Decoder::decode(addsub_carry(0, 1, 1, 31)).unwrap();
        assert_eq!(sbcs.mnemonic, Mnemonic::NGCS);
        assert!(sbcs.sets_flags);
        assert_eq!(sbcs.operands.len(), 2);
        assert!(matches!(sbcs.operands.get(0), Some(Operand::Reg(reg)) if *reg == Register::w(0)));
        assert!(matches!(sbcs.operands.get(1), Some(Operand::Reg(reg)) if *reg == Register::w(2)));
    }

    #[test]
    fn test_rbit() {
        // RBIT X0, X1: dac00020
        let insn = decode_bytes(&[0x20, 0x00, 0xc0, 0xda]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::RBIT);
    }

    #[test]
    fn test_rev() {
        // REV X0, X1: dac00c20
        let insn = decode_bytes(&[0x20, 0x0c, 0xc0, 0xda]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::REV);

        // REV W0, W1: 5ac00820
        let insn = decode_bytes(&[0x20, 0x08, 0xc0, 0x5a]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::REV);
    }

    #[test]
    fn test_clz() {
        // CLZ X0, X1: dac01020
        let insn = decode_bytes(&[0x20, 0x10, 0xc0, 0xda]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::CLZ);
    }

    #[test]
    fn test_dp_1_source_rejects_reserved_opcode2_values() {
        for raw in [
            0xdac0_0020, // RBIT X0, X1
            0xdac0_0420, // REV16 X0, X1
            0xdac0_0820, // REV32 X0, X1
            0xdac0_0c20, // REV X0, X1
            0xdac0_1020, // CLZ X0, X1
            0xdac0_1420, // CLS X0, X1
        ] {
            for opcode2 in 2..=0x1F {
                let insn = Aarch64Decoder::decode(raw | (opcode2 << 16)).unwrap();
                assert_eq!(insn.mnemonic, Mnemonic::UNKNOWN);
            }
        }
    }

    #[test]
    fn test_scalar_fp_decoder_classifies_by_subfields() {
        // #48: the scalar FP routing sent every [28:24]=11110, [21]=1 encoding
        // to the 2-source decoder, but floating-point compare / conditional
        // compare / conditional select / immediate forms all share bit 21 and
        // are distinguished by finer subfields ([11:10], [14:10], [13:10]).
        // The old fallthrough table actively mis-decoded several of them, and
        // reserved type 0b10 aliased to single precision in both the 2- and
        // 3-source helpers.
        let fp_size = |insn: &DecodedInsn, idx: usize| match insn.operands[idx] {
            Operand::FpReg(r) => r.size,
            ref other => panic!("operand {idx} not an FP reg: {other:?}"),
        };

        // --- 2-source still decodes correctly (must not regress) ---
        // FADD S0,S1,S2 / FADD D0,D1,D2 / FDIV S0,S1,S2
        assert_eq!(
            Aarch64Decoder::decode(0x1E22_2820).unwrap().mnemonic,
            Mnemonic::FADD
        );
        assert_eq!(
            Aarch64Decoder::decode(0x1E62_2820).unwrap().mnemonic,
            Mnemonic::FADD
        );
        assert_eq!(
            Aarch64Decoder::decode(0x1E22_1820).unwrap().mnemonic,
            Mnemonic::FDIV
        );
        assert_eq!(
            fp_size(&Aarch64Decoder::decode(0x1E22_2820).unwrap(), 0),
            FpRegSize::S
        );
        assert_eq!(
            fp_size(&Aarch64Decoder::decode(0x1E62_2820).unwrap(), 0),
            FpRegSize::D
        );

        // --- 1-source still decodes correctly ---
        // FABS S0,S1 / FNEG S0,S1
        assert_eq!(
            Aarch64Decoder::decode(0x1E20_C020).unwrap().mnemonic,
            Mnemonic::FABS
        );
        assert_eq!(
            Aarch64Decoder::decode(0x1E21_4020).unwrap().mnemonic,
            Mnemonic::FNEG
        );

        // --- the fix: classes that merely share bit 21 must not mis-decode ---
        // FCSEL S0,S1,S2,NE ([11:10]=11): old table read [15:10]=0x07 as FCMP.
        let fcsel = Aarch64Decoder::decode(0x1E22_1C20).unwrap();
        assert_eq!(fcsel.mnemonic, Mnemonic::FCSEL);
        assert_eq!(fp_size(&fcsel, 0), FpRegSize::S);
        assert!(matches!(
            fcsel.operands.get(3),
            Some(Operand::Cond(Condition::NE))
        ));
        // FCCMP S1,S2,#0,EQ ([11:10]=01): old table read [15:10]=0x01 as FCMP.
        assert_eq!(
            Aarch64Decoder::decode(0x1E22_0420).unwrap().mnemonic,
            Mnemonic::UNKNOWN
        );
        // FCMP S1,S2 ([13:10]=1000): compare class, not 2-source arithmetic.
        let fcmp = Aarch64Decoder::decode(0x1E22_2020).unwrap();
        assert_eq!(fcmp.mnemonic, Mnemonic::FCMP);
        assert_eq!(fcmp.operands.len(), 2);
        assert_eq!(fp_size(&fcmp, 0), FpRegSize::S);

        // --- reserved type 0b10 must be undefined, not aliased to single ---
        // 2-source FADD-shaped word with ptype=0b10.
        assert_eq!(
            Aarch64Decoder::decode(0x1EA2_2820).unwrap().mnemonic,
            Mnemonic::UNDEFINED
        );

        // --- 3-source: half precision keeps H, reserved 0b10 is undefined ---
        // FMADD H0,H1,H2,H3 (type=0b11): old `size & 1` mislabeled the size as D.
        let fmadd_h = Aarch64Decoder::decode(0x1FC2_0C20).unwrap();
        assert_eq!(fmadd_h.mnemonic, Mnemonic::FMADD);
        assert_eq!(fp_size(&fmadd_h, 0), FpRegSize::H);
        // type=0b10 reserved → undefined (old `size & 1` aliased it to single).
        assert_eq!(
            Aarch64Decoder::decode(0x1F82_0C20).unwrap().mnemonic,
            Mnemonic::UNDEFINED
        );
    }

    #[test]
    fn test_lsl_reg() {
        // LSL X0, X1, X2: 9ac22020
        let insn = decode_bytes(&[0x20, 0x20, 0xc2, 0x9a]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::LSL);
    }

    #[test]
    fn test_lsr_reg() {
        // LSR X0, X1, X2: 9ac22420
        let insn = decode_bytes(&[0x20, 0x24, 0xc2, 0x9a]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::LSR);
    }

    #[test]
    fn test_asr_reg() {
        // ASR X0, X1, X2: 9ac22820
        let insn = decode_bytes(&[0x20, 0x28, 0xc2, 0x9a]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::ASR);
    }

    #[test]
    fn test_tbz() {
        // TBZ X0, #0, #0x10: 36000080
        let insn = decode_bytes(&[0x80, 0x00, 0x00, 0x36]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::TBZ);
    }

    #[test]
    fn test_tbnz() {
        // TBNZ X0, #0, #0x10: 37000080
        let insn = decode_bytes(&[0x80, 0x00, 0x00, 0x37]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::TBNZ);
    }

    #[test]
    fn test_br() {
        // BR X0: d61f0000
        let insn = decode_bytes(&[0x00, 0x00, 0x1f, 0xd6]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::BR);
    }

    #[test]
    fn test_blr() {
        // BLR X0: d63f0000
        let insn = decode_bytes(&[0x00, 0x00, 0x3f, 0xd6]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::BLR);
    }

    #[test]
    fn test_neg() {
        // NEG X0, X1 -> SUB X0, XZR, X1: cb0103e0
        let insn = decode_bytes(&[0xe0, 0x03, 0x01, 0xcb]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::NEG);
    }

    #[test]
    fn test_shifted_subs_prefers_cmp_over_negs_when_rd_is_zr() {
        // CMP XZR, X1 -> SUBS XZR, XZR, X1: eb0103ff. This encoding also
        // has Rn == XZR, but CMP is the preferred alias because Rd == XZR.
        let insn = decode_bytes(&[0xff, 0x03, 0x01, 0xeb]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::CMP);
        assert!(insn.sets_flags);
        assert_eq!(insn.operands.len(), 2);
        assert!(
            matches!(insn.operands.get(0), Some(Operand::Reg(reg)) if *reg == Register::zr(true))
        );
        assert!(matches!(insn.operands.get(1), Some(Operand::Reg(reg)) if *reg == Register::x(1)));
    }

    #[test]
    fn test_add_sub_extended_reserved_fixed_bits_decode_unknown() {
        fn addsub_extended(bits23_22: u32) -> u32 {
            (1 << 31)
                | (0b01011 << 24)
                | ((bits23_22 & 0x3) << 22)
                | (1 << 21)
                | (2 << 16)
                | (3 << 13)
                | (1 << 5)
        }

        for bits23_22 in 1..=3 {
            let insn = Aarch64Decoder::decode(addsub_extended(bits23_22)).unwrap();
            assert_eq!(insn.mnemonic, Mnemonic::UNKNOWN);
        }
    }

    #[test]
    fn test_extract_reserved_opc_decode_undefined() {
        fn extract_reserved(opc: u32) -> u32 {
            (opc << 29) | (0b100111 << 23) | (2 << 16) | (7 << 10) | (1 << 5)
        }

        for opc in 1..=3 {
            let insn = Aarch64Decoder::decode(extract_reserved(opc)).unwrap();
            assert_eq!(insn.mnemonic, Mnemonic::UNDEFINED);
        }
    }

    #[test]
    fn test_cond_compare_reserved_s_bit_decode_undefined() {
        fn cond_compare_s_clear(op: u32, imm: bool) -> u32 {
            (op << 30) | (0b11010010 << 21) | (2 << 16) | ((imm as u32) << 11) | (1 << 5)
        }

        for op in 0..=1 {
            for imm in [false, true] {
                let insn = Aarch64Decoder::decode(cond_compare_s_clear(op, imm)).unwrap();
                assert_eq!(insn.mnemonic, Mnemonic::UNDEFINED);
            }
        }
    }

    #[test]
    fn test_sve_pred_true_false_fixed_fields_decode_unknown() {
        fn ptrue(sz: u32, pat: u32, s: u32) -> u32 {
            (0x25 << 24)
                | (sz << 22)
                | ((0b011000 | s) << 16)
                | (0b111000 << 10)
                | ((pat & 0x1F) << 5)
        }

        for raw in [ptrue(0, 0, 0), ptrue(3, 31, 1)] {
            let insn = Aarch64Decoder::decode(raw).unwrap();
            assert_eq!(insn.mnemonic, Mnemonic::SVE_PTRUE);
        }

        let insn = Aarch64Decoder::decode(0x2518_E400).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::SVE_PFALSE);

        for raw in [
            0x25ee_e1fb,
            ptrue(0, 0, 0) | (1 << 4),
            (0x25 << 24) | (3 << 22) | (0b10111 << 17) | (0b111000 << 10),
            0x2518_E400 | (1 << 16),
            0x2518_E400 | (1 << 5),
            0x2518_E400 | (1 << 4),
        ] {
            let insn = Aarch64Decoder::decode(raw).unwrap();
            assert_eq!(insn.mnemonic, Mnemonic::UNKNOWN);
        }
    }

    #[test]
    fn test_sve_int_mla_mls_decode() {
        fn enc(size: u32, sub: bool, zm: u32, pg: u32, zn: u32, zda: u32) -> u32 {
            (0x04 << 24)
                | (size << 22)
                | ((zm & 0x1F) << 16)
                | ((0b010 | (sub as u32)) << 13)
                | ((pg & 0x7) << 10)
                | ((zn & 0x1F) << 5)
                | (zda & 0x1F)
        }

        let mla = Aarch64Decoder::decode(0x041c_50a5).unwrap();
        assert_eq!(mla.mnemonic, Mnemonic::SVE_MLA);

        let mls = Aarch64Decoder::decode(enc(3, true, 31, 7, 30, 29)).unwrap();
        assert_eq!(mls.mnemonic, Mnemonic::SVE_MLS);
    }

    #[test]
    fn test_mvn() {
        // MVN X0, X1 -> ORN X0, XZR, X1: aa2103e0
        let insn = decode_bytes(&[0xe0, 0x03, 0x21, 0xaa]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::MVN);
    }

    #[test]
    fn test_tst_shifted_reg() {
        // TST X0, X1 -> ANDS XZR, X0, X1: ea01001f
        let insn = decode_bytes(&[0x1f, 0x00, 0x01, 0xea]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::TST);
    }

    #[test]
    fn test_32bit_operations() {
        // ADD W0, W1, W2: 0b020020
        let insn = decode_bytes(&[0x20, 0x00, 0x02, 0x0b]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::ADD);

        if let Some(Operand::Reg(reg)) = insn.operands.first() {
            assert!(!reg.is_64bit);
        }
    }

    #[test]
    fn test_conditional_branch() {
        // B.EQ #0x10: 54000080
        let insn = decode_bytes(&[0x80, 0x00, 0x00, 0x54]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::BCC);
        assert_eq!(insn.cond, Some(Condition::EQ));
    }

    // =========================================================================
    // ADR/ADRP - PC-relative addressing (ASL compliance tests)
    // ASL Reference: arch_decode.asl PC-rel addressing
    // Encoding: op (bit 31), immlo (bits 30:29), 10000 (bits 28:24),
    //           immhi (bits 23:5), Rd (bits 4:0)
    // =========================================================================

    #[test]
    fn test_adr_basic() {
        // ADR X0, #0x40 (bit 31 = 0 means ADR)
        // Encoding: 0 00 10000 0000000000000100 00000 = 0x10000800
        let insn = decode_bytes(&[0x00, 0x08, 0x00, 0x10]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::ADR);
        assert_eq!(insn.state, ExecutionState::Aarch64);
    }

    #[test]
    fn test_adr_different_register() {
        // ADR X15, #0x40
        let insn = decode_bytes(&[0x0f, 0x08, 0x00, 0x10]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::ADR);
        // Check destination register is X15
        if let Some(Operand::Reg(reg)) = insn.operands.first() {
            assert_eq!(reg.num, 15);
            assert!(reg.is_64bit);
        } else {
            panic!("Expected register operand");
        }
    }

    #[test]
    fn test_adr_negative_offset() {
        // ADR X0, #-4 (negative offset uses sign-extended immediate)
        // Encoding: op=0, immlo=11, 10000, immhi=1111111111111111111, rd=00000
        // op(31)=0, immlo(30:29)=11, 10000(28:24), immhi(23:5)=all 1s, rd(4:0)=0
        // = 0 11 10000 1111111111111111111 00000
        // = 0111_0000_1111_1111_1111_1111_1110_0000
        // = 0x70FFFFE0
        let insn = decode_bytes(&[0xe0, 0xff, 0xff, 0x70]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::ADR);
        // Check the label is negative
        if let Some(Operand::Label(offset)) = insn.operands.get(1) {
            assert!(*offset < 0, "Expected negative offset, got {}", offset);
        } else {
            panic!("Expected label operand");
        }
    }

    #[test]
    fn test_adrp_basic() {
        // ADRP X0, #0x1000 (bit 31 = 1 means ADRP)
        // Encoding: 1 00 10000 0000000000000001 00000 = 0x90000020
        let insn = decode_bytes(&[0x20, 0x00, 0x00, 0x90]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::ADRP);
        assert_eq!(insn.state, ExecutionState::Aarch64);
    }

    #[test]
    fn test_adrp_different_register() {
        // ADRP X30, #0x1000
        let insn = decode_bytes(&[0x3e, 0x00, 0x00, 0x90]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::ADRP);
        // Check destination register is X30
        if let Some(Operand::Reg(reg)) = insn.operands.first() {
            assert_eq!(reg.num, 30);
            assert!(reg.is_64bit);
        } else {
            panic!("Expected register operand");
        }
    }

    #[test]
    fn test_adrp_page_aligned() {
        // ADRP produces 4KB page-aligned addresses (imm << 12)
        // ADRP X0, #0x2000 -> label should be 0x2000 (page 2)
        let insn = decode_bytes(&[0x40, 0x00, 0x00, 0x90]).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::ADRP);
        if let Some(Operand::Label(offset)) = insn.operands.get(1) {
            // The offset should be a multiple of 4096 (page size)
            assert_eq!(*offset % 4096, 0);
        }
    }

    #[test]
    fn test_adr_vs_adrp_bit31_difference() {
        // Same encoding except bit 31 - should produce different mnemonics
        // Base encoding with immlo=0, immhi=1, rd=0

        // ADR: bit 31 = 0 -> 0x10000020
        let adr_insn = decode_bytes(&[0x20, 0x00, 0x00, 0x10]).unwrap();
        assert_eq!(adr_insn.mnemonic, Mnemonic::ADR);

        // ADRP: bit 31 = 1 -> 0x90000020
        let adrp_insn = decode_bytes(&[0x20, 0x00, 0x00, 0x90]).unwrap();
        assert_eq!(adrp_insn.mnemonic, Mnemonic::ADRP);
    }
}

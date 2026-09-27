//! AArch32 (A32) instruction decoder.
//!
//! This module decodes 32-bit ARM instructions (AArch32/A32).
//! All A32 instructions are 32 bits wide.

use super::{Condition, DecodeError, DecodedInsn, Mnemonic, ShiftType, operand::*};
use crate::isa::arm::ExecutionState;

mod neon;
mod vfp;

#[cfg(test)]
mod tests;

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

        // Synchronization primitives (LDREX/STREX and byte/half/double
        // variants): cccc 0001 1xxL Rn Rd 1111 1001 Rm. Same bits[7:4]=1001
        // as the multiply space, so peel them off first. The executor reads
        // the registers straight from `raw` (A32 layout).
        if raw & 0x0F80_0FF0 == 0x0180_0F90 {
            let op = (raw >> 20) & 0x7; // L:sz
            let mnemonic = match op {
                0b000 => Some(Mnemonic::STXR),
                0b001 => Some(Mnemonic::LDXR),
                0b010 => Some(Mnemonic::STXP), // STREXD
                0b011 => Some(Mnemonic::LDXP), // LDREXD
                0b100 => Some(Mnemonic::STXRB),
                0b101 => Some(Mnemonic::LDXRB),
                0b110 => Some(Mnemonic::STXRH),
                0b111 => Some(Mnemonic::LDXRH),
                _ => None,
            };
            if let Some(m) = mnemonic {
                let insn = DecodedInsn::new(m, ExecutionState::Aarch32, raw, 4);
                return Ok(if cond != Condition::AL {
                    insn.with_cond(cond)
                } else {
                    insn
                });
            }
        }

        // SWP/SWPB: cccc 0001 0B00 Rn Rd 0000 1001 Rm. Shares bits[7:4]=1001
        // with the multiply space, so it must be peeled off first.
        if raw & 0x0FB0_0FF0 == 0x0100_0090 {
            let insn = DecodedInsn::new(Mnemonic::SWP, ExecutionState::Aarch32, raw, 4);
            return Ok(if cond != Condition::AL {
                insn.with_cond(cond)
            } else {
                insn
            });
        }

        // MRS/MSR live in the data-processing TST/TEQ/CMP/CMN hole (op=10xx,
        // S=0), so they must be peeled off before the generic DP decode:
        //   MRS:     cccc 0001 0R00 1111 Rd   0000 0000 0000
        //   MSR reg: cccc 0001 0R10 mask 1111 0000 0000 Rm
        //   MSR imm: cccc 0011 0R10 mask 1111 imm12
        let psr_xfer = if raw & 0x0FBF_0FFF == 0x010F_0000 {
            Some(Mnemonic::MRS)
        } else if raw & 0x0FB0_FFF0 == 0x0120_F000
            || (raw & 0x0FB0_F000 == 0x0320_F000 && raw & 0x000F_0000 != 0)
        {
            // MSR register / MSR immediate; the immediate form with mask=0000
            // is the hint space (NOP/YIELD/WFE/WFI/SEV), not MSR.
            Some(Mnemonic::MSR)
        } else {
            None
        };
        if let Some(m) = psr_xfer {
            let insn = DecodedInsn::new(m, ExecutionState::Aarch32, raw, 4);
            return Ok(if cond != Condition::AL {
                insn.with_cond(cond)
            } else {
                insn
            });
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
        // PLD/PLDW/PLI (preload hints): 1111 01xx U x01/UR01 Rn 1111 ... —
        // load/store-class encodings with Rt=0b1111. Architecturally hints;
        // executed as NOPs.
        if raw & 0x0C10_F000 == 0x0410_F000 {
            return Ok(DecodedInsn::new(
                Mnemonic::NOP,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        // CPS<effect> {#mode}: 1111 0001 0000 imod M 0 xxxx xxxx AIF 0 mode
        if raw & 0xFFF1_FE20 == 0xF100_0000 {
            return Ok(DecodedInsn::new(
                Mnemonic::CPS,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }
        // SRS{<amode>} sp{!}, #mode: 1111 100P U1W0 1101 0000 0101 000 mode
        if raw & 0xFE5F_FFE0 == 0xF84D_0500 {
            return Ok(DecodedInsn::new(
                Mnemonic::SRS,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }
        // RFE{<amode>} Rn{!}: 1111 100P U0W1 Rn 0000 1010 0000 0000
        if raw & 0xFE50_FFFF == 0xF810_0A00 {
            return Ok(DecodedInsn::new(
                Mnemonic::RFE,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        if let Some(insn) = Self::decode_neon_vext(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_table_lookup(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_vmvn_register(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_vrev_register(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_vswp(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_recip_estimate(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_compare_zero(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_vrint(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_directed_convert(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_vdup_scalar(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_fp_fixed_convert(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_fp16_convert(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_fp_convert(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_pairwise_add_long(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_pairwise_integer(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_pairwise_permute(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_abs_neg(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_saturating_abs_neg(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_count_register(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_saturating_add_sub(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_saturating_doubling_mulh(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_saturating_doubling_mulh_scalar(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_fp_multiply_scalar(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_fp16_fused_multiply_long(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_shift_right_immediate(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_widen_move(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_narrow_move(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_shift_narrow_immediate(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_modified_immediate(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_integer_multiply_scalar(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_long_multiply_scalar(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_polynomial_multiply_long(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_long_wide_add_sub(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_narrow_add_sub(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_long_multiply(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_fp_pairwise(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_fp_add_sub(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_fp_minmax(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_fp_fma(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_fp_multiply(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_fp_absdiff(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_integer_absdiff_long(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_integer_absdiff_accum(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_integer_minmax(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_halving_add_sub(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_fp_compare(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_recip_step(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_integer_compare(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_shift_register(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_integer_multiply(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_polynomial_multiply(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_integer_add_sub(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_logical_register(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_vld_all_lanes(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_vld_vst_single_lane(raw) {
            return Ok(insn);
        }

        if let Some(insn) = Self::decode_neon_vld_vst_multiple(raw) {
            return Ok(insn);
        }

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
                return Ok(DecodedInsn::new(
                    Mnemonic::A32_SAT_ADDSUB,
                    ExecutionState::Aarch32,
                    raw,
                    4,
                )
                .with_operand(Operand::Reg(Register::raw(rd, false, false)))
                .with_operand(Operand::Reg(Register::raw(rm, false, false)))
                .with_operand(Operand::Reg(Register::raw(rn, false, false))));
            }
            if (op2 & 0b1001) == 0b1000 {
                // Halfword/word multiplies: SMLA/SMUL/SMLAW/SMULW/SMLAL<x><y>
                return Ok(
                    DecodedInsn::new(Mnemonic::A32_HMUL, ExecutionState::Aarch32, raw, 4)
                        .with_operand(Operand::Reg(Register::raw(rd, false, false))),
                );
            }
            // The rest of the miscellaneous space (bit 7 clear; op = bits
            // 22:21, op2 = bits 6:4): BKPT, BXJ, ERET, HVC, SMC. Anything
            // else there (the banked MRS/MSR of the Virtualization
            // Extensions among it) is UNDEFINED, never data processing.
            if op2 & 0b1000 == 0 {
                let mk = |m| DecodedInsn::new(m, ExecutionState::Aarch32, raw, 4);
                return Ok(match ((raw >> 21) & 0b11, op2 & 0b111) {
                    (0b01, 0b111) => mk(Mnemonic::BKPT),
                    // BXJ with a trivial Jazelle implementation (ARMv8, and
                    // ARMv7 with Jazelle disabled) is BX.
                    (0b01, 0b010) => return Self::decode_bx(raw),
                    (0b11, 0b110) => mk(Mnemonic::ERET),
                    (0b10, 0b111) => mk(Mnemonic::HVC),
                    (0b11, 0b111) => mk(Mnemonic::SMC),
                    _ => mk(Mnemonic::UNKNOWN),
                });
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
        let register_shift = (raw >> 4) & 1 != 0;
        let rs = ((raw >> 8) & 0xF) as u8;
        let rm = (raw & 0xF) as u8;

        let (mnemonic, uses_rn, writes_rd) = Self::dp_opcode_to_mnemonic(opcode, s == 1);

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4);

        if s == 1 {
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

        if register_shift {
            insn = insn.with_operand(Operand::ShiftedReg(ShiftedRegister::by_register(
                rm_reg,
                shift_type,
                Register::raw(rs, false, false),
            )));
        } else if shift_imm == 0 && shift_type == ShiftType::LSL {
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
            // L=0 with op1 10/11 are the dual load/store (bits[7:4]=1101/1111).
            // LDP/STP are the shared exec entry points for LDRD/STRD.
            (0, 0b10) => Mnemonic::LDP,
            (0, 0b11) => Mnemonic::STP,
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
        if let Some(insn) = Self::decode_vfp_pair_register_transfer(raw) {
            return Ok(insn);
        }
        if let Some(insn) = Self::decode_vfp_load_store(raw) {
            return Ok(insn);
        }

        let l = (raw >> 20) & 1;

        let mnemonic = if l == 1 { Mnemonic::LDC } else { Mnemonic::STC };

        Ok(DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4))
    }

    fn decode_coprocessor_dp(raw: u32) -> Result<DecodedInsn, DecodeError> {
        if let Some(insn) = Self::decode_vfp_conditional_select(raw) {
            return Ok(insn);
        }
        if let Some(insn) = Self::decode_vfp_minmaxnm(raw) {
            return Ok(insn);
        }
        if let Some(insn) = Self::decode_vfp_directed_round(raw) {
            return Ok(insn);
        }
        if let Some(insn) = Self::decode_vfp_directed_convert(raw) {
            return Ok(insn);
        }
        if let Some(insn) = Self::decode_neon_vdup_register(raw) {
            return Ok(insn);
        }
        if let Some(insn) = Self::decode_vfp_transfer_or_system(raw) {
            return Ok(insn);
        }
        if let Some(insn) = Self::decode_vfp_data_processing(raw) {
            return Ok(insn);
        }

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

        // Integer divide (ARMv7 with the divide extension):
        // cccc 0111 00x1 Rd 1111 Rm 0001 Rn, where x selects UDIV/SDIV.
        // Unlike most media encodings, Rd occupies bits 19:16 and the two
        // sources occupy bits 3:0 (dividend) and 11:8 (divisor).
        let divide = match raw & 0x0ff0_f0f0 {
            0x0730_f010 => Some(Mnemonic::UDIV),
            0x0710_f010 => Some(Mnemonic::SDIV),
            _ => None,
        };
        if let Some(mnemonic) = divide {
            let div_rd = ((raw >> 16) & 0xf) as u8;
            let div_rn = (raw & 0xf) as u8;
            let div_rm = ((raw >> 8) & 0xf) as u8;
            return mk(mnemonic, &[div_rd, div_rn, div_rm]);
        }

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

        // Bit-field: SBFX (1101x, op2 x10), BFI/BFC (1110x, op2 x00), UBFX
        // (1111x, op2 x10); and UDF, the permanently UNDEFINED 11111/111.
        match (op1 >> 1, op2 & 0b011) {
            _ if op1 == 0b11111 && op2 == 0b111 => return mk(Mnemonic::UDF, &[]),
            (0b1101, 0b10) => return mk(Mnemonic::SBFX, &[rd]),
            (0b1110, 0b00) => {
                if (raw & 0xF) == 0xF {
                    return mk(Mnemonic::BFC, &[rd]);
                } else {
                    return mk(Mnemonic::BFI, &[rd]);
                }
            }
            (0b1111, 0b10) => return mk(Mnemonic::UBFX, &[rd]),
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

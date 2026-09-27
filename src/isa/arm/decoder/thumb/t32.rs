//! Thumb-2 (T32) decoders: load/store multiple and dual, data processing
//! (modified and plain immediates, registers), branches and miscellaneous
//! control, multiplies and divides, and single loads and stores.

use super::*;

impl ThumbDecoder {
    pub(super) fn decode_32bit_load_store_multiple(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let l = (raw >> 20) & 1;
        let w = (raw >> 21) & 1;
        let rn = ((raw >> 16) & 0xF) as u8;
        let reg_list = (raw & 0xFFFF) as u16;

        // op = bits[24:23]: 01 = increment-after, 10 = decrement-before.
        let mnemonic = match ((raw >> 23) & 3, l) {
            (0b01, 1) => Mnemonic::LDMIA,
            (0b01, 0) => Mnemonic::STMIA,
            (0b10, 1) => Mnemonic::LDMDB,
            (0b10, 0) => Mnemonic::STMDB,
            _ => Mnemonic::UNKNOWN,
        };

        // PUSH is STMDB SP! and POP is LDMIA SP!; STMIA SP! and LDMDB SP!
        // keep their own names (they move SP the other way).
        let mnemonic = match mnemonic {
            Mnemonic::STMDB if rn == 13 && w == 1 => Mnemonic::PUSH,
            Mnemonic::LDMIA if rn == 13 && w == 1 => Mnemonic::POP,
            m => m,
        };

        let is_push_pop = matches!(mnemonic, Mnemonic::PUSH | Mnemonic::POP);

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Thumb2, raw, 4);

        if !is_push_pop {
            insn = insn.with_operand(Operand::Reg(Self::any_reg(rn)));
        }

        insn = insn.with_operand(Operand::RegList(RegisterList::from_mask(reg_list)));

        Ok(insn)
    }

    pub(super) fn decode_32bit_load_store_dual(raw: u32) -> Result<DecodedInsn, DecodeError> {
        // LDRD/STRD (immediate): op1 = P:U:1:W (bit24..21), L = bit20; P and
        // W both clear are the exclusive, acquire/release, and table-branch
        // members of the group.
        let p = (raw >> 24) & 1;
        let u = (raw >> 23) & 1;
        let w = (raw >> 21) & 1;
        let l = (raw >> 20) & 1;
        if p == 0 && w == 0 {
            return Ok(Self::decode_32bit_exclusive(raw));
        }
        let rn = ((raw >> 16) & 0xF) as u8; // hw1[3:0]
        let rt = ((raw >> 12) & 0xF) as u8; // hw2[15:12]
        let rt2 = ((raw >> 8) & 0xF) as u8; // hw2[11:8]
        let imm8 = (raw & 0xFF) as i64; // hw2[7:0]
        let off = if u == 1 { imm8 << 2 } else { -(imm8 << 2) };
        let mode = if p == 0 {
            AddressingMode::PostIndex
        } else if w == 1 {
            AddressingMode::PreIndex
        } else {
            AddressingMode::Offset
        };
        let mnemonic = if l == 1 { Mnemonic::LDP } else { Mnemonic::STP };
        Ok(DecodedInsn::new(mnemonic, ExecutionState::Thumb2, raw, 4)
            .with_operand(Operand::Reg(Self::any_reg(rt)))
            .with_operand(Operand::Reg(Self::any_reg(rt2)))
            .with_operand(Operand::Mem(MemOperand {
                base: Self::any_reg(rn),
                offset: MemOffset::Imm(off),
                mode,
            })))
    }

    /// LDREX and STREX (`1110 1000 010L`, with an `imm8:'00'` offset), and
    /// TBB, TBH, the byte, halfword, and doubleword exclusives, and the
    /// ARMv8 load-acquires and store-releases (`1110 1000 110L`, selected
    /// by hw2[7:4]). Named as the A32 decoder names them; the executor
    /// reads the registers from `raw` in the T32 layout.
    fn decode_32bit_exclusive(raw: u32) -> DecodedInsn {
        let u = (raw >> 23) & 1;
        let l = (raw >> 20) & 1;
        let op3 = (raw >> 4) & 0xF;
        let mnemonic = match (u, l, op3) {
            (0, 0, _) => Mnemonic::STXR,
            (0, 1, _) => Mnemonic::LDXR,
            (1, 1, 0b0000) => Mnemonic::TBB,
            (1, 1, 0b0001) => Mnemonic::TBH,
            (1, 0, 0b0100) => Mnemonic::STXRB,
            (1, 1, 0b0100) => Mnemonic::LDXRB,
            (1, 0, 0b0101) => Mnemonic::STXRH,
            (1, 1, 0b0101) => Mnemonic::LDXRH,
            (1, 0, 0b0111) => Mnemonic::STXP, // STREXD
            (1, 1, 0b0111) => Mnemonic::LDXP, // LDREXD
            (1, 0, 0b1000) => Mnemonic::STLRB,
            (1, 1, 0b1000) => Mnemonic::LDARB,
            (1, 0, 0b1001) => Mnemonic::STLRH,
            (1, 1, 0b1001) => Mnemonic::LDARH,
            (1, 0, 0b1010) => Mnemonic::STLR, // STL
            (1, 1, 0b1010) => Mnemonic::LDAR, // LDA
            (1, 0, 0b1100) => Mnemonic::STLXRB,
            (1, 1, 0b1100) => Mnemonic::LDAXRB,
            (1, 0, 0b1101) => Mnemonic::STLXRH,
            (1, 1, 0b1101) => Mnemonic::LDAXRH,
            (1, 0, 0b1110) => Mnemonic::STLXR, // STLEX
            (1, 1, 0b1110) => Mnemonic::LDAXR, // LDAEX
            (1, 0, 0b1111) => Mnemonic::STLXP, // STLEXD
            (1, 1, 0b1111) => Mnemonic::LDAXP, // LDAEXD
            _ => Mnemonic::UNKNOWN,
        };
        DecodedInsn::new(mnemonic, ExecutionState::Thumb2, raw, 4)
    }

    /// T32 data-processing (shifted register): AND/BIC/ORR/ORN/EOR/PKH/ADD/ADC/
    /// SBC/SUB/RSB with a shifted Rm, plus the MOV/MVN-with-shift and the
    /// TST/TEQ/CMP/CMN comparison forms.
    pub(super) fn decode_32bit_data_processing(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let hw1 = (raw >> 16) as u16;
        let hw2 = raw as u16;

        let op = (hw1 >> 5) & 0xF;
        let s = (hw1 >> 4) & 1;
        let rn = (hw1 & 0xF) as u8;
        let rd = ((hw2 >> 8) & 0xF) as u8;
        let rm = (hw2 & 0xF) as u8;
        let imm3 = (hw2 >> 12) & 0x7;
        let imm2 = (hw2 >> 6) & 0x3;
        let type_bits = (hw2 >> 4) & 0x3;
        let shift_imm = ((imm3 << 2) | imm2) as u8;

        // Decode the shift type/amount (RRX when type==11 && shift==0).
        let (shift_type, amount) = match type_bits {
            0b00 => (ShiftType::LSL, shift_imm),
            0b01 => (ShiftType::LSR, if shift_imm == 0 { 32 } else { shift_imm }),
            0b10 => (ShiftType::ASR, if shift_imm == 0 { 32 } else { shift_imm }),
            _ => {
                if shift_imm == 0 {
                    (ShiftType::RRX, 1)
                } else {
                    (ShiftType::ROR, shift_imm)
                }
            }
        };

        // PKHBT / PKHTB (op==0110): route to the A32 umbrella (T32-aware exec).
        if op == 0b0110 {
            return Ok(
                DecodedInsn::new(Mnemonic::A32_PKH, ExecutionState::Thumb2, raw, 4)
                    .with_operand(Operand::Reg(Self::any_reg(rd))),
            );
        }

        let (mnemonic, uses_rn, writes_rd) = match op {
            0b0000 => {
                if rd == 15 && s == 1 {
                    (Mnemonic::TST, true, false)
                } else {
                    (
                        if s == 1 {
                            Mnemonic::ANDS
                        } else {
                            Mnemonic::AND
                        },
                        true,
                        true,
                    )
                }
            }
            0b0001 => (
                if s == 1 {
                    Mnemonic::BICS
                } else {
                    Mnemonic::BIC
                },
                true,
                true,
            ),
            0b0010 => {
                if rn == 15 {
                    (
                        if s == 1 {
                            Mnemonic::MOVS
                        } else {
                            Mnemonic::MOV
                        },
                        false,
                        true,
                    )
                } else {
                    (
                        if s == 1 {
                            Mnemonic::ORRS
                        } else {
                            Mnemonic::ORR
                        },
                        true,
                        true,
                    )
                }
            }
            0b0011 => {
                if rn == 15 {
                    (
                        if s == 1 {
                            Mnemonic::MVNS
                        } else {
                            Mnemonic::MVN
                        },
                        false,
                        true,
                    )
                } else {
                    (
                        if s == 1 {
                            Mnemonic::ORNS
                        } else {
                            Mnemonic::ORN
                        },
                        true,
                        true,
                    )
                }
            }
            0b0100 => {
                if rd == 15 && s == 1 {
                    (Mnemonic::TEQ, true, false)
                } else {
                    (
                        if s == 1 {
                            Mnemonic::EORS
                        } else {
                            Mnemonic::EOR
                        },
                        true,
                        true,
                    )
                }
            }
            0b1000 => {
                if rd == 15 && s == 1 {
                    (Mnemonic::CMN, true, false)
                } else {
                    (
                        if s == 1 {
                            Mnemonic::ADDS
                        } else {
                            Mnemonic::ADD
                        },
                        true,
                        true,
                    )
                }
            }
            0b1010 => (
                if s == 1 {
                    Mnemonic::ADCS
                } else {
                    Mnemonic::ADC
                },
                true,
                true,
            ),
            0b1011 => (
                if s == 1 {
                    Mnemonic::SBCS
                } else {
                    Mnemonic::SBC
                },
                true,
                true,
            ),
            0b1101 => {
                if rd == 15 && s == 1 {
                    (Mnemonic::CMP, true, false)
                } else {
                    (
                        if s == 1 {
                            Mnemonic::SUBS
                        } else {
                            Mnemonic::SUB
                        },
                        true,
                        true,
                    )
                }
            }
            0b1110 => (
                if s == 1 {
                    Mnemonic::RSBS
                } else {
                    Mnemonic::RSB
                },
                true,
                true,
            ),
            _ => (Mnemonic::UNKNOWN, false, false),
        };

        if mnemonic == Mnemonic::UNKNOWN {
            return Ok(DecodedInsn::new(
                Mnemonic::UNKNOWN,
                ExecutionState::Thumb2,
                raw,
                4,
            ));
        }

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Thumb2, raw, 4);
        if s == 1 && writes_rd {
            insn.sets_flags = true;
        }
        if writes_rd {
            insn = insn.with_operand(Operand::Reg(Self::any_reg(rd)));
        }
        if uses_rn {
            insn = insn.with_operand(Operand::Reg(Self::any_reg(rn)));
        }
        insn = insn.with_operand(Operand::ShiftedReg(ShiftedRegister::new(
            Self::any_reg(rm),
            shift_type,
            amount,
        )));
        Ok(insn)
    }

    pub(super) fn decode_32bit_dp_modified_imm(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let hw1 = (raw >> 16) as u16;
        let hw2 = raw as u16;

        let op = (hw1 >> 5) & 0xF;
        let rn = (hw1 & 0xF) as u8;
        let s = (hw1 >> 4) & 1;
        let rd = ((hw2 >> 8) & 0xF) as u8;

        // Decode modified immediate
        let i = (hw1 >> 10) & 1;
        let imm3 = (hw2 >> 12) & 0x7;
        let imm8 = (hw2 & 0xFF) as u32;
        let imm12 = ((i as u32) << 11) | ((imm3 as u32) << 8) | imm8;
        let imm = Self::decode_thumb_modified_imm(imm12);

        let (mnemonic, uses_rn, writes_rd) = match op {
            0b0000 => {
                if rd == 15 && s == 1 {
                    (Mnemonic::TST, true, false)
                } else {
                    (
                        if s == 1 {
                            Mnemonic::ANDS
                        } else {
                            Mnemonic::AND
                        },
                        true,
                        true,
                    )
                }
            }
            0b0001 => (
                if s == 1 {
                    Mnemonic::BICS
                } else {
                    Mnemonic::BIC
                },
                true,
                true,
            ),
            0b0010 => {
                if rn == 15 {
                    (
                        if s == 1 {
                            Mnemonic::MOVS
                        } else {
                            Mnemonic::MOV
                        },
                        false,
                        true,
                    )
                } else {
                    (
                        if s == 1 {
                            Mnemonic::ORRS
                        } else {
                            Mnemonic::ORR
                        },
                        true,
                        true,
                    )
                }
            }
            0b0011 => {
                if rn == 15 {
                    (
                        if s == 1 {
                            Mnemonic::MVNS
                        } else {
                            Mnemonic::MVN
                        },
                        false,
                        true,
                    )
                } else {
                    (
                        if s == 1 {
                            Mnemonic::ORNS
                        } else {
                            Mnemonic::ORN
                        },
                        true,
                        true,
                    )
                }
            }
            0b0100 => {
                if rd == 15 && s == 1 {
                    (Mnemonic::TEQ, true, false)
                } else {
                    (
                        if s == 1 {
                            Mnemonic::EORS
                        } else {
                            Mnemonic::EOR
                        },
                        true,
                        true,
                    )
                }
            }
            0b1000 => {
                if rd == 15 && s == 1 {
                    (Mnemonic::CMN, true, false)
                } else {
                    (
                        if s == 1 {
                            Mnemonic::ADDS
                        } else {
                            Mnemonic::ADD
                        },
                        true,
                        true,
                    )
                }
            }
            0b1010 => (
                if s == 1 {
                    Mnemonic::ADCS
                } else {
                    Mnemonic::ADC
                },
                true,
                true,
            ),
            0b1011 => (
                if s == 1 {
                    Mnemonic::SBCS
                } else {
                    Mnemonic::SBC
                },
                true,
                true,
            ),
            0b1101 => {
                if rd == 15 && s == 1 {
                    (Mnemonic::CMP, true, false)
                } else {
                    (
                        if s == 1 {
                            Mnemonic::SUBS
                        } else {
                            Mnemonic::SUB
                        },
                        true,
                        true,
                    )
                }
            }
            0b1110 => (
                if s == 1 {
                    Mnemonic::RSBS
                } else {
                    Mnemonic::RSB
                },
                true,
                true,
            ),
            _ => (Mnemonic::UNKNOWN, false, false),
        };

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Thumb2, raw, 4);

        if s == 1 && writes_rd {
            insn.sets_flags = true;
        }

        if writes_rd {
            insn = insn.with_operand(Operand::Reg(Self::any_reg(rd)));
        }

        if uses_rn {
            insn = insn.with_operand(Operand::Reg(Self::any_reg(rn)));
        }

        insn = insn.with_operand(Operand::Imm(Immediate::new(imm as i64)));

        Ok(insn)
    }

    /// T32 data-processing (plain binary immediate): ADDW/SUBW/MOVW/MOVT and the
    /// bitfield/saturate group. Exec for the bitfield/sat ops reads the T32 raw
    /// layout (state == Thumb2); ADDW/SUBW/MOVW/MOVT are lowered to ADD/SUB/MOV/
    /// MOVK with an immediate operand.
    pub(super) fn decode_32bit_dp_plain_imm(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let hw1 = (raw >> 16) as u16;
        let hw2 = raw as u16;
        let op = (hw1 >> 4) & 0x1F;
        let rn = (hw1 & 0xF) as u8;
        let rd = ((hw2 >> 8) & 0xF) as u8;
        let i = ((hw1 >> 10) & 1) as u32;
        let imm3 = ((hw2 >> 12) & 0x7) as u32;
        let imm8 = (hw2 & 0xFF) as u32;
        let shift_imm = (imm3 << 2) | (((hw2 >> 6) & 0x3) as u32);
        let imm12 = (i << 11) | (imm3 << 8) | imm8;
        let imm16 = ((rn as u32) << 12) | imm12;

        let reg = |n: u8| Operand::Reg(Self::any_reg(n));
        let mk = |m: Mnemonic, ops: Vec<Operand>| {
            let mut insn = DecodedInsn::new(m, ExecutionState::Thumb2, raw, 4);
            for o in ops {
                insn = insn.with_operand(o);
            }
            Ok(insn)
        };

        match op {
            0b00000 => mk(
                Mnemonic::ADD,
                vec![reg(rd), reg(rn), Operand::Imm(Immediate::new(imm12 as i64))],
            ),
            0b01010 => mk(
                Mnemonic::SUB,
                vec![reg(rd), reg(rn), Operand::Imm(Immediate::new(imm12 as i64))],
            ),
            0b00100 => mk(
                Mnemonic::MOV,
                vec![reg(rd), Operand::Imm(Immediate::new(imm16 as i64))],
            ),
            0b01100 => mk(
                Mnemonic::MOVK,
                vec![reg(rd), Operand::Imm(Immediate::new(imm16 as i64))],
            ),
            0b10000 => mk(Mnemonic::SSAT, vec![reg(rd)]),
            0b10010 => {
                if shift_imm == 0 {
                    mk(Mnemonic::A32_SAT16, vec![reg(rd)])
                } else {
                    mk(Mnemonic::SSAT, vec![reg(rd)])
                }
            }
            0b10100 => mk(Mnemonic::SBFX, vec![reg(rd)]),
            0b10110 => {
                if rn == 15 {
                    mk(Mnemonic::BFC, vec![reg(rd)])
                } else {
                    mk(Mnemonic::BFI, vec![reg(rd)])
                }
            }
            0b11000 => mk(Mnemonic::USAT, vec![reg(rd)]),
            0b11010 => {
                if shift_imm == 0 {
                    mk(Mnemonic::A32_SAT16, vec![reg(rd)])
                } else {
                    mk(Mnemonic::USAT, vec![reg(rd)])
                }
            }
            0b11100 => mk(Mnemonic::UBFX, vec![reg(rd)]),
            _ => Ok(DecodedInsn::new(
                Mnemonic::UNKNOWN,
                ExecutionState::Thumb2,
                raw,
                4,
            )),
        }
    }

    fn decode_thumb_modified_imm(imm12: u32) -> u32 {
        let imm8 = imm12 & 0xFF;
        if (imm12 >> 10) & 0x3 == 0 {
            // Replicated patterns, selected by imm12[9:8].
            match (imm12 >> 8) & 0x3 {
                0b00 => imm8,
                0b01 => (imm8 << 16) | imm8,
                0b10 => (imm8 << 24) | (imm8 << 8),
                _ => (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8,
            }
        } else {
            // Rotated: value = 0x80:imm12[6:0], rotated right by imm12[11:7].
            let val = 0x80 | (imm12 & 0x7F);
            val.rotate_right((imm12 >> 7) & 0x1F)
        }
    }

    pub(super) fn decode_32bit_branch_misc(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let hw1 = (raw >> 16) as u16;
        let hw2 = raw as u16;

        let op1 = (hw1 >> 4) & 0x7F;
        let op2 = (hw2 >> 12) & 0x7;

        // Conditional branch
        if op2 & 0x5 == 0 && op1 & 0x38 != 0x38 {
            let s = (hw1 >> 10) & 1;
            let cond = ((hw1 >> 6) & 0xF) as u8;
            let imm6 = hw1 & 0x3F;
            let j1 = (hw2 >> 13) & 1;
            let j2 = (hw2 >> 11) & 1;
            let imm11 = hw2 & 0x7FF;

            let imm = ((s as u32) << 20)
                | ((j2 as u32) << 19)
                | ((j1 as u32) << 18)
                | ((imm6 as u32) << 12)
                | ((imm11 as u32) << 1);

            // Sign extend
            let offset = if s == 1 {
                (imm | 0xFFE0_0000) as i32
            } else {
                imm as i32
            } as i64;

            return Ok(
                DecodedInsn::new(Mnemonic::BCC, ExecutionState::Thumb2, raw, 4)
                    .with_cond(Condition::from_bits(cond))
                    .with_operand(Operand::Label(offset)),
            );
        }

        // Unconditional branch (B.W, BL, BLX)
        // BL:  hw2[15:14] = 11, hw2[12] = 1 → op2 = x1x where bit 0 = 1
        // BLX: hw2[15:14] = 11, hw2[12] = 0 → op2 = x0x where bit 0 = 0
        // B.W: hw2[15:14] = 10, hw2[12] = x → op2 bit 2 = 0
        if op2 & 0x4 == 0x4 || (op2 & 0x5 == 0x1) {
            let s = (hw1 >> 10) & 1;
            let imm10 = hw1 & 0x3FF;
            let j1 = (hw2 >> 13) & 1;
            let j2 = (hw2 >> 11) & 1;
            let imm11 = hw2 & 0x7FF;
            let link_bit = (hw2 >> 14) & 1; // L bit
            let exchange_bit = (hw2 >> 12) & 1; // For BLX, this is 0

            let i1 = !((j1 ^ s) & 1) & 1;
            let i2 = !((j2 ^ s) & 1) & 1;

            let imm = ((s as u32) << 24)
                | ((i1 as u32) << 23)
                | ((i2 as u32) << 22)
                | ((imm10 as u32) << 12)
                | ((imm11 as u32) << 1);

            // Sign extend
            let offset = if s == 1 {
                (imm | 0xFE00_0000) as i32
            } else {
                imm as i32
            } as i64;

            let mnemonic = if link_bit == 1 && exchange_bit == 0 {
                Mnemonic::BLX
            } else if link_bit == 1 {
                Mnemonic::BL
            } else {
                Mnemonic::B
            };

            return Ok(DecodedInsn::new(mnemonic, ExecutionState::Thumb2, raw, 4)
                .with_operand(Operand::Label(offset)));
        }

        Ok(Self::decode_32bit_misc_control(raw))
    }

    /// The rest of "Branches and miscellaneous control" (op2 = 0x0 with
    /// op1 = x111xxx, and UDF): MSR and MRS (the banked forms, hw2 bit 5
    /// set, are not decoded), the hints and CPS, CLREX and the barriers,
    /// and UDF. BXJ, ERET, HVC, and SMC are not decoded either.
    fn decode_32bit_misc_control(raw: u32) -> DecodedInsn {
        let hw1 = (raw >> 16) as u16;
        let hw2 = raw as u16;
        let op1 = (hw1 >> 4) & 0x7F;
        let op2 = (hw2 >> 12) & 0x7;
        let banked = hw2 & 0x20 != 0;
        let insn = |m| DecodedInsn::new(m, ExecutionState::Thumb2, raw, 4);
        match (op1, op2) {
            (0x38 | 0x39, 0b000 | 0b010) if !banked => insn(Mnemonic::MSR),
            (0x3A, 0b000 | 0b010) if hw2 & 0x0700 == 0 => insn(match hw2 & 0xFF {
                0 => Mnemonic::NOP,
                1 => Mnemonic::YIELD,
                2 => Mnemonic::WFE,
                3 => Mnemonic::WFI,
                4 => Mnemonic::SEV,
                5 => Mnemonic::SEVL,
                _ => Mnemonic::HINT,
            }),
            (0x3A, 0b000 | 0b010) => insn(Mnemonic::CPS),
            (0x3B, 0b000 | 0b010) => {
                let option = Operand::Barrier(BarrierOption::from_bits((hw2 & 0xF) as u8));
                match (hw2 >> 4) & 0xF {
                    0b0010 => insn(Mnemonic::CLREX),
                    0b0100 => insn(Mnemonic::DSB).with_operand(option),
                    0b0101 => insn(Mnemonic::DMB).with_operand(option),
                    0b0110 => insn(Mnemonic::ISB).with_operand(option),
                    0b0111 => insn(Mnemonic::SB),
                    _ => insn(Mnemonic::UNKNOWN),
                }
            }
            (0x3E | 0x3F, 0b000 | 0b010) if !banked => insn(Mnemonic::MRS),
            (0x7F, 0b010) => insn(Mnemonic::UDF),
            _ => insn(Mnemonic::UNKNOWN),
        }
    }

    /// T32 data-processing (register): register-controlled shifts (LSL/LSR/ASR/
    /// ROR), register extends, parallel add/sub, and the miscellaneous ops
    /// (QADD/QSUB/QDADD/QDSUB, REV/REV16/RBIT/REVSH, SEL, CLZ).
    pub(super) fn decode_32bit_dp_register(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let hw1 = (raw >> 16) as u16;
        let hw2 = raw as u16;
        let op1 = (hw1 >> 4) & 0xF; // bits[23:20]
        let op2 = (hw2 >> 4) & 0xF; // bits[7:4]
        let rn = (hw1 & 0xF) as u8;
        let rd = ((hw2 >> 8) & 0xF) as u8;
        let rm = (hw2 & 0xF) as u8;
        let any = Self::any_reg;

        let mk = |m: Mnemonic, ops: &[u8], flags: bool| {
            let mut insn = DecodedInsn::new(m, ExecutionState::Thumb2, raw, 4);
            insn.sets_flags = flags;
            for &o in ops {
                insn = insn.with_operand(Operand::Reg(any(o)));
            }
            insn
        };

        if op2 & 0b1000 == 0 {
            if op1 & 0b1000 == 0 {
                // Register-controlled shift: type = op1[2:1], S = op1[0].
                let s = op1 & 1 == 1;
                let (base, sbase) = match (op1 >> 1) & 0x3 {
                    0 => (Mnemonic::LSL, Mnemonic::LSLS),
                    1 => (Mnemonic::LSR, Mnemonic::LSRS),
                    2 => (Mnemonic::ASR, Mnemonic::ASRS),
                    _ => (Mnemonic::ROR, Mnemonic::RORS),
                };
                let m = if s { sbase } else { base };
                // operands: [Rd, Rn(value), Rm(shift amount)]
                return Ok(mk(m, &[rd, rn, rm], s));
            } else {
                // Parallel add/sub.
                return Ok(mk(Mnemonic::A32_PARALLEL, &[rd, rn, rm], false));
            }
        } else if op1 & 0b1000 == 0 {
            // Register extends (op1 in 0..5).
            if rn == 15 {
                let mnemonic = match op1 {
                    0 => Some(Mnemonic::SXTH),
                    1 => Some(Mnemonic::UXTH),
                    4 => Some(Mnemonic::SXTB),
                    5 => Some(Mnemonic::UXTB),
                    _ => None,
                };
                if let Some(mnemonic) = mnemonic {
                    let rotate = ((op2 & 0x3) * 8) as u8;
                    let source = if rotate == 0 {
                        Operand::Reg(any(rm))
                    } else {
                        Operand::ShiftedReg(ShiftedRegister::new(any(rm), ShiftType::ROR, rotate))
                    };
                    return Ok(DecodedInsn::new(mnemonic, ExecutionState::Thumb2, raw, 4)
                        .with_operand(Operand::Reg(any(rd)))
                        .with_operand(source));
                }
            }
            return Ok(mk(Mnemonic::A32_EXTEND, &[rd, rn, rm], false));
        } else {
            // Miscellaneous operations, keyed by op1[2:0] and op2[1:0].
            match op1 & 0x7 {
                0b000 => return Ok(mk(Mnemonic::A32_SAT_ADDSUB, &[rd, rn, rm], false)),
                0b001 => {
                    let m = match op2 & 0x3 {
                        0b00 => Mnemonic::REV,
                        0b01 => Mnemonic::REV16,
                        0b10 => Mnemonic::RBIT,
                        _ => Mnemonic::REVSH,
                    };
                    return Ok(mk(m, &[rd, rm], false));
                }
                0b010 => return Ok(mk(Mnemonic::A32_SEL, &[rd, rn, rm], false)),
                0b011 => return Ok(mk(Mnemonic::CLZ, &[rd, rm], false)),
                _ => {}
            }
        }

        Ok(DecodedInsn::new(
            Mnemonic::UNKNOWN,
            ExecutionState::Thumb2,
            raw,
            4,
        ))
    }

    pub(super) fn decode_32bit_multiply(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let hw1 = (raw >> 16) as u16;
        let hw2 = raw as u16;

        let op1 = (hw1 >> 4) & 0x7;
        let op2 = (hw2 >> 4) & 0x3;
        let rn = (hw1 & 0xF) as u8;
        let ra = ((hw2 >> 12) & 0xF) as u8;
        let rd = ((hw2 >> 8) & 0xF) as u8;
        let rm = (hw2 & 0xF) as u8;

        // DSP signed multiplies use the A32 umbrella mnemonics; their exec reads
        // the T32 raw layout (state == Thumb2).
        let dsp = match op1 {
            0b001 | 0b011 => Some(Mnemonic::A32_HMUL), // SMUL/SMLA + SMULW/SMLAW
            0b010 | 0b100 => Some(Mnemonic::A32_DUAL), // SMUAD/SMLAD + SMUSD/SMLSD
            0b101 | 0b110 => Some(Mnemonic::A32_SMMUL), // SMMUL/SMMLA + SMMLS
            0b111 => Some(Mnemonic::A32_USAD),         // USAD8/USADA8
            _ => None,
        };
        if let Some(m) = dsp {
            return Ok(DecodedInsn::new(m, ExecutionState::Thumb2, raw, 4)
                .with_operand(Operand::Reg(Self::any_reg(rd))));
        }

        let mnemonic = match (op1, op2) {
            (0b000, 0b00) if ra != 15 => Mnemonic::MLA,
            (0b000, 0b00) if ra == 15 => Mnemonic::MUL,
            (0b000, 0b01) => Mnemonic::MLS,
            _ => Mnemonic::UNKNOWN,
        };

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Thumb2, raw, 4)
            .with_operand(Operand::Reg(Self::any_reg(rd)))
            .with_operand(Operand::Reg(Self::any_reg(rn)))
            .with_operand(Operand::Reg(Self::any_reg(rm)));

        if mnemonic == Mnemonic::MLA || mnemonic == Mnemonic::MLS {
            insn = insn.with_operand(Operand::Reg(Self::any_reg(ra)));
        }

        Ok(insn)
    }

    pub(super) fn decode_32bit_long_multiply_divide(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let hw1 = (raw >> 16) as u16;
        let hw2 = raw as u16;

        let op1 = (hw1 >> 4) & 0x7;
        let op2 = (hw2 >> 4) & 0xF;
        let rn = (hw1 & 0xF) as u8;
        let rd_lo = ((hw2 >> 12) & 0xF) as u8;
        let rd_hi = ((hw2 >> 8) & 0xF) as u8;
        let rm = (hw2 & 0xF) as u8;

        // UMAAL / SMLALD / SMLSLD use the umbrella mnemonics (exec reads T32 raw).
        // SMLALD/SMLSLD: op1=100/101 with op2=110x. UMAAL: op1=110, op2=0110.
        if (op1 == 0b100 || op1 == 0b101) && (op2 & 0xE) == 0xC {
            return Ok(
                DecodedInsn::new(Mnemonic::A32_SMLALD, ExecutionState::Thumb2, raw, 4)
                    .with_operand(Operand::Reg(Self::any_reg(rd_lo))),
            );
        }
        if op1 == 0b110 && op2 == 0b0110 {
            return Ok(
                DecodedInsn::new(Mnemonic::UMAAL, ExecutionState::Thumb2, raw, 4)
                    .with_operand(Operand::Reg(Self::any_reg(rd_lo)))
                    .with_operand(Operand::Reg(Self::any_reg(rd_hi)))
                    .with_operand(Operand::Reg(Self::any_reg(rn)))
                    .with_operand(Operand::Reg(Self::any_reg(rm))),
            );
        }

        let mnemonic = match (op1, op2) {
            (0b000, 0b0000) => Mnemonic::SMULL,
            (0b001, 0b1111) => Mnemonic::SDIV,
            (0b010, 0b0000) => Mnemonic::UMULL,
            (0b011, 0b1111) => Mnemonic::UDIV,
            (0b100, 0b0000) => Mnemonic::SMLAL,
            (0b110, 0b0000) => Mnemonic::UMLAL,
            _ => Mnemonic::UNKNOWN,
        };

        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Thumb2, raw, 4);

        match mnemonic {
            Mnemonic::SDIV | Mnemonic::UDIV => {
                insn = insn
                    .with_operand(Operand::Reg(Self::any_reg(rd_hi))) // Actually Rd
                    .with_operand(Operand::Reg(Self::any_reg(rn)))
                    .with_operand(Operand::Reg(Self::any_reg(rm)));
            }
            Mnemonic::SMULL | Mnemonic::UMULL | Mnemonic::SMLAL | Mnemonic::UMLAL => {
                insn = insn
                    .with_operand(Operand::Reg(Self::any_reg(rd_lo)))
                    .with_operand(Operand::Reg(Self::any_reg(rd_hi)))
                    .with_operand(Operand::Reg(Self::any_reg(rn)))
                    .with_operand(Operand::Reg(Self::any_reg(rm)));
            }
            _ => {}
        }

        Ok(insn)
    }

    /// Build the T32 single load/store memory operand, covering T3 (positive
    /// imm12), T4 (±imm8 with offset/pre/post-index + writeback), and the
    /// register-offset (LSL imm2) form.
    fn t32_mem_operand(raw: u32) -> MemOperand {
        let hw1 = (raw >> 16) as u16;
        let hw2 = raw as u16;
        let base = Self::any_reg((hw1 & 0xF) as u8);
        if base.num == 15 {
            // T32 literal loads use Rn=PC and encode U in hw1 bit 7 plus a
            // full imm12 in hw2.  They are not T4/register-offset forms: in
            // particular, a subtracting literal with imm12[11]=0 previously
            // fell through to the register-offset decoder and treated the low
            // nibble of the displacement as Rm.
            let imm12 = (hw2 & 0xFFF) as i64;
            let offset = if (hw1 >> 7) & 1 == 1 { imm12 } else { -imm12 };
            return MemOperand::imm_offset(base, offset);
        }
        if (hw1 >> 7) & 1 == 1 {
            // T3: positive 12-bit immediate offset.
            MemOperand::imm_offset(base, (hw2 & 0xFFF) as i64)
        } else if (hw2 >> 11) & 1 == 1 {
            // T4: ±imm8 with P/U/W.
            let p = (hw2 >> 10) & 1;
            let u = (hw2 >> 9) & 1;
            let w = (hw2 >> 8) & 1;
            let imm8 = (hw2 & 0xFF) as i64;
            let off = if u == 1 { imm8 } else { -imm8 };
            let mode = if p == 0 {
                AddressingMode::PostIndex
            } else if w == 1 {
                AddressingMode::PreIndex
            } else {
                AddressingMode::Offset
            };
            MemOperand {
                base,
                offset: MemOffset::Imm(off),
                mode,
            }
        } else {
            // Register offset, optional LSL by imm2.
            let imm2 = ((hw2 >> 4) & 0x3) as u8;
            let rm = Self::any_reg((hw2 & 0xF) as u8);
            let offset = if imm2 == 0 {
                MemOffset::Reg(rm)
            } else {
                MemOffset::ShiftedReg(ShiftedRegister::new(rm, ShiftType::LSL, imm2))
            };
            MemOperand {
                base,
                offset,
                mode: AddressingMode::Offset,
            }
        }
    }

    pub(super) fn decode_32bit_load_byte(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let hw1 = (raw >> 16) as u16;
        let rt = ((raw >> 12) & 0xF) as u8;
        let mnemonic = if (hw1 >> 8) & 1 == 0 {
            Mnemonic::LDRB
        } else {
            Mnemonic::LDRSB
        };
        Ok(DecodedInsn::new(mnemonic, ExecutionState::Thumb2, raw, 4)
            .with_operand(Operand::Reg(Self::any_reg(rt)))
            .with_operand(Operand::Mem(Self::t32_mem_operand(raw))))
    }

    pub(super) fn decode_32bit_load_halfword(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let hw1 = (raw >> 16) as u16;
        let rt = ((raw >> 12) & 0xF) as u8;
        let mnemonic = if (hw1 >> 8) & 1 == 1 {
            Mnemonic::LDRSH
        } else {
            Mnemonic::LDRH
        };
        Ok(DecodedInsn::new(mnemonic, ExecutionState::Thumb2, raw, 4)
            .with_operand(Operand::Reg(Self::any_reg(rt)))
            .with_operand(Operand::Mem(Self::t32_mem_operand(raw))))
    }

    pub(super) fn decode_32bit_load_word(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let rt = ((raw >> 12) & 0xF) as u8;
        Ok(
            DecodedInsn::new(Mnemonic::LDR, ExecutionState::Thumb2, raw, 4)
                .with_operand(Operand::Reg(Self::any_reg(rt)))
                .with_operand(Operand::Mem(Self::t32_mem_operand(raw))),
        )
    }

    pub(super) fn decode_32bit_store(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let hw1 = (raw >> 16) as u16;
        let rt = ((raw >> 12) & 0xF) as u8;
        let mnemonic = match (hw1 >> 5) & 0x3 {
            0b00 => Mnemonic::STRB,
            0b01 => Mnemonic::STRH,
            0b10 => Mnemonic::STR,
            _ => Mnemonic::UNKNOWN,
        };
        Ok(DecodedInsn::new(mnemonic, ExecutionState::Thumb2, raw, 4)
            .with_operand(Operand::Reg(Self::any_reg(rt)))
            .with_operand(Operand::Mem(Self::t32_mem_operand(raw))))
    }
}

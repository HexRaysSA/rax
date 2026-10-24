//! Authenticated branches, loads, and HINT aliases (Arm A64 XML 2025-12).

use super::*;

impl Aarch64Decoder {
    pub(super) fn decode_uncond_branch_reg(raw: u32) -> Result<DecodedInsn, DecodeError> {
        let opc = (raw >> 21) & 0xf;
        let op2 = (raw >> 16) & 0x1f;
        let op3 = (raw >> 10) & 0x3f;
        let rn = ((raw >> 5) & 0x1f) as u8;
        let rm = (raw & 0x1f) as u8;
        let mnemonic = if op2 != 31 {
            Mnemonic::UNDEFINED
        } else {
            match (opc, op3, rm) {
                (0, 0, 0) => Mnemonic::BR,
                (1, 0, 0) => Mnemonic::BLR,
                (2, 0, 0) => Mnemonic::RET,
                (4, 0, 0) if rn == 31 => Mnemonic::ERET,
                (5, 0, 0) if rn == 31 => Mnemonic::DRPS,
                (8, 2, _) => Mnemonic::BRAA,
                (8, 3, _) => Mnemonic::BRAB,
                (9, 2, _) => Mnemonic::BLRAA,
                (9, 3, _) => Mnemonic::BLRAB,
                (0, 2, 31) => Mnemonic::BRAAZ,
                (0, 3, 31) => Mnemonic::BRABZ,
                (1, 2, 31) => Mnemonic::BLRAAZ,
                (1, 3, 31) => Mnemonic::BLRABZ,
                (2, 2, 31) if rn == 31 => Mnemonic::RETAA,
                (2, 3, 31) if rn == 31 => Mnemonic::RETAB,
                (4, 2, 31) if rn == 31 => Mnemonic::ERETAA,
                (4, 3, 31) if rn == 31 => Mnemonic::ERETAB,
                _ => Mnemonic::UNDEFINED,
            }
        };
        let mut insn = DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4);
        match mnemonic {
            Mnemonic::BR
            | Mnemonic::BLR
            | Mnemonic::RET
            | Mnemonic::BRAAZ
            | Mnemonic::BRABZ
            | Mnemonic::BLRAAZ
            | Mnemonic::BLRABZ => {
                insn = insn.with_operand(Operand::Reg(Register::with_zr(rn, true)));
            }
            Mnemonic::BRAA | Mnemonic::BRAB | Mnemonic::BLRAA | Mnemonic::BLRAB => {
                insn = insn
                    .with_operand(Operand::Reg(Register::with_zr(rn, true)))
                    .with_operand(Operand::Reg(Register::with_sp(rm, true)));
            }
            _ => {}
        }
        Ok(insn)
    }

    pub(super) fn decode_pauth_load(raw: u32) -> Option<DecodedInsn> {
        // size=11, V=0, fixed bits[29:24]=111000, bit21=1, bit10=1.
        if raw & 0xff20_0400 != 0xf820_0400 {
            return None;
        }
        let rn = ((raw >> 5) & 31) as u8;
        let rt = (raw & 31) as u8;
        let writeback = raw & (1 << 11) != 0;
        let mnemonic = if writeback && rn == rt && rn != 31 {
            // ConstrainUnpredictable(WBOVERLAPLD): select Constraint_UNDEF.
            Mnemonic::UNDEFINED
        } else if raw & (1 << 23) == 0 {
            Mnemonic::LDRAA
        } else {
            Mnemonic::LDRAB
        };
        let imm10 = (((raw >> 22) & 1) << 9) | ((raw >> 12) & 0x1ff);
        let offset = (((imm10 << 22) as i32 >> 22) as i64) << 3;
        Some(
            DecodedInsn::new(mnemonic, ExecutionState::Aarch64, raw, 4)
                .with_operand(Operand::Reg(Register::with_zr(rt, true)))
                .with_operand(Operand::Mem(MemOperand {
                    base: Register::with_sp(rn, true),
                    offset: MemOffset::Imm(offset),
                    mode: if writeback {
                        AddressingMode::PreIndex
                    } else {
                        AddressingMode::Offset
                    },
                })),
        )
    }

    pub(super) fn pauth_hint_mnemonic(imm: u8) -> Option<Mnemonic> {
        Some(match imm {
            7 => Mnemonic::XPACLRI,
            8 => Mnemonic::PACIA1716,
            10 => Mnemonic::PACIB1716,
            12 => Mnemonic::AUTIA1716,
            14 => Mnemonic::AUTIB1716,
            24 => Mnemonic::PACIAZ,
            25 => Mnemonic::PACIASP,
            26 => Mnemonic::PACIBZ,
            27 => Mnemonic::PACIBSP,
            28 => Mnemonic::AUTIAZ,
            29 => Mnemonic::AUTIASP,
            30 => Mnemonic::AUTIBZ,
            31 => Mnemonic::AUTIBSP,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pauth_branches_decode_all_forms_and_modifiers() {
        for (raw, mnemonic) in [
            (0xd71f_0801, Mnemonic::BRAA),
            (0xd71f_0c01, Mnemonic::BRAB),
            (0xd73f_0801, Mnemonic::BLRAA),
            (0xd73f_0c01, Mnemonic::BLRAB),
            (0xd61f_081f, Mnemonic::BRAAZ),
            (0xd61f_0c1f, Mnemonic::BRABZ),
            (0xd63f_081f, Mnemonic::BLRAAZ),
            (0xd63f_0c1f, Mnemonic::BLRABZ),
            (0xd65f_0bff, Mnemonic::RETAA),
            (0xd65f_0fff, Mnemonic::RETAB),
            (0xd69f_0bff, Mnemonic::ERETAA),
            (0xd69f_0fff, Mnemonic::ERETAB),
        ] {
            assert_eq!(
                Aarch64Decoder::decode(raw).unwrap().mnemonic,
                mnemonic,
                "{raw:#010x}"
            );
        }
        let insn = Aarch64Decoder::decode(0xd71f_081f).unwrap();
        assert!(matches!(insn.operands.as_slice(), [Operand::Reg(_), Operand::Reg(r)] if r.is_sp));
        for raw in [0xd61f_0800, 0xd65f_081f, 0xd69f_081f] {
            assert_eq!(
                Aarch64Decoder::decode(raw).unwrap().mnemonic,
                Mnemonic::UNDEFINED
            );
        }
    }

    #[test]
    fn pauth_loads_decode_scaled_signed_offsets_and_writeback() {
        for key_b in [false, true] {
            for immediate in [-512i32, -1, 0, 1, 511] {
                for writeback in [false, true] {
                    let imm10 = immediate as u32 & 0x3ff;
                    let raw = 0xf820_0400
                        | ((key_b as u32) << 23)
                        | ((imm10 >> 9) << 22)
                        | ((imm10 & 0x1ff) << 12)
                        | ((writeback as u32) << 11)
                        | (31 << 5)
                        | 6;
                    let insn = Aarch64Decoder::decode(raw).unwrap();
                    assert_eq!(
                        insn.mnemonic,
                        if key_b {
                            Mnemonic::LDRAB
                        } else {
                            Mnemonic::LDRAA
                        }
                    );
                    let Operand::Mem(mem) = &insn.operands[1] else {
                        panic!("missing memory operand")
                    };
                    assert_eq!(mem.offset, MemOffset::Imm(i64::from(immediate) * 8));
                    assert_eq!(
                        mem.mode,
                        if writeback {
                            AddressingMode::PreIndex
                        } else {
                            AddressingMode::Offset
                        }
                    );
                    assert!(mem.base.is_sp);
                }
            }
        }
        assert_eq!(
            Aarch64Decoder::decode(0xf820_17e6).unwrap().mnemonic,
            Mnemonic::LDRAA
        );
        assert_eq!(
            Aarch64Decoder::decode(0xf820_0c00).unwrap().mnemonic,
            Mnemonic::UNDEFINED
        );
    }

    #[test]
    fn pauth_hint_aliases_are_not_generic_hints() {
        for immediate in [7u32, 8, 10, 12, 14, 24, 25, 26, 27, 28, 29, 30, 31] {
            let raw = 0xd503_201f | (immediate << 5);
            let decoded = Aarch64Decoder::decode(raw).unwrap();
            assert_eq!(
                Some(decoded.mnemonic),
                Aarch64Decoder::pauth_hint_mnemonic(immediate as u8)
            );
        }
    }
}

//! Advanced SIMD element and structure loads and stores (`VLD1`-`VLD4`,
//! `VST1`-`VST4`: multiple structures, single lanes, and all lanes).

use super::super::*;

impl Aarch32Decoder {
    pub(crate) fn decode_neon_vld_all_lanes(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 24) != 0xF4
            || ((raw >> 23) & 1) != 1
            || ((raw >> 21) & 1) != 1
            || ((raw >> 20) & 1) != 0
        {
            return None;
        }

        let ty = (raw >> 8) & 0xF;
        let size = (raw >> 6) & 0x3;
        let a = (raw >> 4) & 1;
        let mnemonic = match ty {
            0b1100 => Mnemonic::VLD1,
            0b1101 => Mnemonic::VLD2,
            0b1110 => Mnemonic::VLD3,
            0b1111 => Mnemonic::VLD4,
            _ => return None,
        };

        let undefined = match mnemonic {
            Mnemonic::VLD1 => size == 0b11 || (size == 0 && a == 1),
            Mnemonic::VLD2 | Mnemonic::VLD3 => {
                size == 0b11 || (mnemonic == Mnemonic::VLD3 && a == 1)
            }
            Mnemonic::VLD4 => size == 0b11 && a == 0,
            _ => false,
        };
        if undefined {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        let rn = ((raw >> 16) & 0xF) as u8;
        Some(
            DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4).with_operand(Operand::Mem(
                MemOperand::imm_offset(Register::raw(rn, false, rn == 13), 0),
            )),
        )
    }

    pub(crate) fn decode_neon_vld_vst_single_lane(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 24) != 0xF4 || ((raw >> 23) & 1) != 1 || ((raw >> 20) & 1) != 0 {
            return None;
        }

        let l = (raw >> 21) & 1;
        let size = (raw >> 10) & 0x3;
        let streams = ((raw >> 8) & 0x3) + 1;
        if l == 1 && size == 0b11 {
            return None;
        }

        let mnemonic = match (l, streams) {
            (1, 1) => Mnemonic::VLD1,
            (1, 2) => Mnemonic::VLD2,
            (1, 3) => Mnemonic::VLD3,
            (1, 4) => Mnemonic::VLD4,
            (0, 1) => Mnemonic::VST1,
            (0, 2) => Mnemonic::VST2,
            (0, 3) => Mnemonic::VST3,
            (0, 4) => Mnemonic::VST4,
            _ => return None,
        };

        let index_align = (raw >> 4) & 0xF;
        if size == 0b11 || !Self::neon_single_lane_index_valid(streams, size, index_align) {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        let rn = ((raw >> 16) & 0xF) as u8;
        Some(
            DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4).with_operand(Operand::Mem(
                MemOperand::imm_offset(Register::raw(rn, false, rn == 13), 0),
            )),
        )
    }

    pub(crate) fn neon_single_lane_index_valid(streams: u32, size: u32, index_align: u32) -> bool {
        match (streams, size) {
            (1, 0) => (index_align & 0b0001) == 0,
            (1, 1) => (index_align & 0b0010) == 0,
            (1, 2) => (index_align & 0b0100) == 0 && matches!(index_align & 0b0011, 0b00 | 0b11),
            (2, 0) => true,
            (2, 1) => true,
            (2, 2) => (index_align & 0b0010) == 0,
            (3, 0) | (3, 1) => (index_align & 0b0001) == 0,
            (3, 2) => (index_align & 0b0011) == 0,
            (4, 0) | (4, 1) => true,
            (4, 2) => (index_align & 0b0011) != 0b0011,
            _ => false,
        }
    }

    pub(crate) fn decode_neon_vld_vst_multiple(raw: u32) -> Option<DecodedInsn> {
        if (raw >> 24) != 0xF4 || ((raw >> 23) & 1) != 0 || ((raw >> 20) & 1) != 0 {
            return None;
        }

        let l = (raw >> 21) & 1;
        let ty = (raw >> 8) & 0xF;
        let size = (raw >> 6) & 0x3;
        let (mnemonic, regs) = match (l, ty) {
            (1, 0b0111) => (Mnemonic::VLD1, 1),
            (1, 0b1010) => (Mnemonic::VLD1, 2),
            (1, 0b0110) => (Mnemonic::VLD1, 3),
            (1, 0b0010) => (Mnemonic::VLD1, 4),
            (0, 0b0111) => (Mnemonic::VST1, 1),
            (0, 0b1010) => (Mnemonic::VST1, 2),
            (0, 0b0110) => (Mnemonic::VST1, 3),
            (0, 0b0010) => (Mnemonic::VST1, 4),
            (1, 0b1000 | 0b1001) => (Mnemonic::VLD2, 1),
            (1, 0b0011) => (Mnemonic::VLD2, 2),
            (0, 0b1000 | 0b1001) => (Mnemonic::VST2, 1),
            (0, 0b0011) => (Mnemonic::VST2, 2),
            (1, 0b0100 | 0b0101) => (Mnemonic::VLD3, 1),
            (0, 0b0100 | 0b0101) => (Mnemonic::VST3, 1),
            (1, 0b0000 | 0b0001) => (Mnemonic::VLD4, 1),
            (0, 0b0000 | 0b0001) => (Mnemonic::VST4, 1),
            _ => return None,
        };

        let align = (raw >> 4) & 0x3;
        if matches!(mnemonic, Mnemonic::VLD2 | Mnemonic::VST2) && size == 0b11 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }
        if matches!(mnemonic, Mnemonic::VLD1 | Mnemonic::VST1)
            && (regs == 1 || regs == 3)
            && (align & 0b10) != 0
        {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }
        if matches!(mnemonic, Mnemonic::VLD1 | Mnemonic::VST1) && regs == 2 && align == 0b11 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }
        if matches!(mnemonic, Mnemonic::VLD2 | Mnemonic::VST2) && regs == 1 && align == 0b11 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }
        if matches!(mnemonic, Mnemonic::VLD3 | Mnemonic::VST3)
            && (size == 0b11 || (align & 0b10) != 0)
        {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }
        if matches!(mnemonic, Mnemonic::VLD4 | Mnemonic::VST4) && size == 0b11 {
            return Some(DecodedInsn::new(
                Mnemonic::UNDEFINED,
                ExecutionState::Aarch32,
                raw,
                4,
            ));
        }

        let rn = ((raw >> 16) & 0xF) as u8;
        Some(
            DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4)
                .with_operand(Operand::Mem(MemOperand::imm_offset(
                    Register::raw(rn, false, rn == 13),
                    0,
                )))
                .with_operand(Operand::Imm(Immediate::new(regs))),
        )
    }
}

//! FP16 scalar/core register moves, Arm VINS/VMOVX/VMOV_h operations.
use super::*;
impl Aarch32Decoder {
    pub(crate) fn decode_vfp_half_register(raw: u32) -> Option<DecodedInsn> {
        if raw & 0x0fe00f10 == 0x0e000910 {
            let t = ((raw >> 12) & 15) as u8;
            let n = ((((raw >> 16) & 15) << 1) | ((raw >> 7) & 1)) as u8;
            // DDI 0597 marks bits 6:5 and 3:0 as (0) for VMOV.F16.
            if raw >> 28 != 14 || t == 15 || raw & 0x6f != 0 {
                return Some(DecodedInsn::new(
                    Mnemonic::UNDEFINED,
                    ExecutionState::Aarch32,
                    raw,
                    4,
                ));
            }
            let fp = Operand::FpReg(FpRegister::s(n));
            let core = Operand::Reg(Register::raw(t, false, t == 13));
            return Some(if raw & (1 << 20) != 0 {
                DecodedInsn::new(Mnemonic::VMOV_F16_CORE, ExecutionState::Aarch32, raw, 4)
                    .with_operand(core)
                    .with_operand(fp)
            } else {
                DecodedInsn::new(Mnemonic::VMOV_F16_CORE, ExecutionState::Aarch32, raw, 4)
                    .with_operand(fp)
                    .with_operand(core)
            });
        }
        let kind = raw & 0xffbf0fd0;
        let mnemonic = match kind {
            0xfeb00a40 => Mnemonic::VMOVX_F16,
            0xfeb00ac0 => Mnemonic::VINS_F16,
            _ => return None,
        };
        let d = ((((raw >> 12) & 15) << 1) | ((raw >> 22) & 1)) as u8;
        let m = (((raw & 15) << 1) | ((raw >> 5) & 1)) as u8;
        Some(
            DecodedInsn::new(mnemonic, ExecutionState::Aarch32, raw, 4)
                .with_operand(Operand::FpReg(FpRegister::s(d)))
                .with_operand(Operand::FpReg(FpRegister::s(m))),
        )
    }
}

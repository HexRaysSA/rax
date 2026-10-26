//! CPACR permission checks shared by every decoded A32/T32 FP/AdvSIMD route.
use super::*;
use crate::isa::arm::decoder::ThumbDecoder;

impl<'a, M: ArmMemory> Executor<'a, M> {
    pub(super) fn fp_access_denied(&self, insn: &DecodedInsn) -> bool {
        let coprocessor = (insn.raw >> 8) & 15;
        let fp_coprocessor = matches!(
            insn.mnemonic,
            Mnemonic::MCR
                | Mnemonic::MRC
                | Mnemonic::MCR2
                | Mnemonic::MRC2
                | Mnemonic::MCRR
                | Mnemonic::MRRC
                | Mnemonic::CDP
                | Mnemonic::CDP2
        ) && matches!(coprocessor, 10 | 11);
        let fp_instruction = matches!(
            insn.mnemonic,
            Mnemonic::VADD
                | Mnemonic::VSUB
                | Mnemonic::VMUL
                | Mnemonic::VDIV
                | Mnemonic::VMLA
                | Mnemonic::VMLS
                | Mnemonic::VSELEQ
                | Mnemonic::VSELGE
                | Mnemonic::VSELGT
                | Mnemonic::VSELVS
                | Mnemonic::VMAXNM_F32
                | Mnemonic::VMAXNM_F64
                | Mnemonic::VMAXNM_F16
                | Mnemonic::VMINNM_F32
                | Mnemonic::VMINNM_F64
                | Mnemonic::VMINNM_F16
                | Mnemonic::VRINTA_F32
                | Mnemonic::VRINTA_F64
                | Mnemonic::VRINTA_F16
                | Mnemonic::VRINTM_F32
                | Mnemonic::VRINTM_F64
                | Mnemonic::VRINTM_F16
                | Mnemonic::VRINTN_F32
                | Mnemonic::VRINTN_F64
                | Mnemonic::VRINTN_F16
                | Mnemonic::VRINTP_F32
                | Mnemonic::VRINTP_F64
                | Mnemonic::VRINTP_F16
                | Mnemonic::VRINTR_F32
                | Mnemonic::VRINTR_F64
                | Mnemonic::VRINTR_F16
                | Mnemonic::VRINTX_F32
                | Mnemonic::VRINTX_F64
                | Mnemonic::VRINTX_F16
                | Mnemonic::VRINTZ_F32
                | Mnemonic::VRINTZ_F64
                | Mnemonic::VRINTZ_F16
                | Mnemonic::VFMA
                | Mnemonic::VFMS
                | Mnemonic::VFMAL
                | Mnemonic::VFMLS
                | Mnemonic::VNMLA
                | Mnemonic::VNMLS
                | Mnemonic::VFNMA
                | Mnemonic::VFNMS
                | Mnemonic::VNMUL
                | Mnemonic::VAND
                | Mnemonic::VORR
                | Mnemonic::VEOR
                | Mnemonic::VBIC
                | Mnemonic::VORN
                | Mnemonic::VBSL
                | Mnemonic::VBIT
                | Mnemonic::VBIF
                | Mnemonic::VMOV
                | Mnemonic::VMOVL
                | Mnemonic::VMOVN
                | Mnemonic::VQMOVN
                | Mnemonic::VQMOVUN
                | Mnemonic::VMRS
                | Mnemonic::VMSR
                | Mnemonic::VMVN
                | Mnemonic::VCLS
                | Mnemonic::VCLZ
                | Mnemonic::VCNT
                | Mnemonic::VREV16
                | Mnemonic::VREV32
                | Mnemonic::VREV64
                | Mnemonic::VSWP
                | Mnemonic::VDUP
                | Mnemonic::VEXT
                | Mnemonic::VSHL
                | Mnemonic::VSHR
                | Mnemonic::VRSHR
                | Mnemonic::VSRA
                | Mnemonic::VRSRA
                | Mnemonic::VRSHL
                | Mnemonic::VQSHL
                | Mnemonic::VQRSHL
                | Mnemonic::VQSHLU
                | Mnemonic::VSHRN
                | Mnemonic::VRSHRN
                | Mnemonic::VQSHRN
                | Mnemonic::VQRSHRN
                | Mnemonic::VQSHRUN
                | Mnemonic::VQRSHRUN
                | Mnemonic::VSLI
                | Mnemonic::VSRI
                | Mnemonic::VZIP
                | Mnemonic::VUZP
                | Mnemonic::VTRN
                | Mnemonic::VPADD
                | Mnemonic::VPADDL
                | Mnemonic::VPADAL
                | Mnemonic::VPMAX
                | Mnemonic::VPMIN
                | Mnemonic::VTBL
                | Mnemonic::VTBX
                | Mnemonic::VHADD
                | Mnemonic::VRHADD
                | Mnemonic::VHSUB
                | Mnemonic::VCEQ
                | Mnemonic::VCGT
                | Mnemonic::VCGE
                | Mnemonic::VTST
                | Mnemonic::VCLE
                | Mnemonic::VCLT
                | Mnemonic::VACGT
                | Mnemonic::VACGE
                | Mnemonic::VQADD
                | Mnemonic::VQSUB
                | Mnemonic::VQDMULH
                | Mnemonic::VQRDMULH
                | Mnemonic::VQABS
                | Mnemonic::VQNEG
                | Mnemonic::VABD
                | Mnemonic::VABA
                | Mnemonic::VABDL
                | Mnemonic::VABAL
                | Mnemonic::VADDL
                | Mnemonic::VADDW
                | Mnemonic::VADDHN
                | Mnemonic::VRADDHN
                | Mnemonic::VMULL
                | Mnemonic::VMLAL
                | Mnemonic::VMLSL
                | Mnemonic::VQDMULL
                | Mnemonic::VQDMLAL
                | Mnemonic::VQDMLSL
                | Mnemonic::VSUBL
                | Mnemonic::VSUBW
                | Mnemonic::VSUBHN
                | Mnemonic::VRSUBHN
                | Mnemonic::VCMP
                | Mnemonic::VCMPE
                | Mnemonic::VABS
                | Mnemonic::VNEG
                | Mnemonic::VSQRT
                | Mnemonic::VRECPE
                | Mnemonic::VRSQRTE
                | Mnemonic::VRECPS
                | Mnemonic::VRSQRTS
                | Mnemonic::VCVT_F32_S32
                | Mnemonic::VCVT_F32_U32
                | Mnemonic::VCVT_F16_S32
                | Mnemonic::VCVT_F16_U32
                | Mnemonic::VCVT_S32_F32
                | Mnemonic::VCVT_U32_F32
                | Mnemonic::VCVT_S32_F16
                | Mnemonic::VCVT_U32_F16
                | Mnemonic::VCVT_F64_S32
                | Mnemonic::VCVT_F64_U32
                | Mnemonic::VCVT_S32_F64
                | Mnemonic::VCVT_U32_F64
                | Mnemonic::VCVT_F64_F32
                | Mnemonic::VCVT_F32_F64
                | Mnemonic::VCVT_F16_F32
                | Mnemonic::VCVT_F32_F16
                | Mnemonic::VCVTB_F32_F16
                | Mnemonic::VCVTT_F32_F16
                | Mnemonic::VCVTB_F16_F32
                | Mnemonic::VCVTT_F16_F32
                | Mnemonic::VCVT_F32_S32_FIXED
                | Mnemonic::VCVT_F32_U32_FIXED
                | Mnemonic::VCVT_S32_F32_FIXED
                | Mnemonic::VCVT_U32_F32_FIXED
                | Mnemonic::VCVT_F64_S32_FIXED
                | Mnemonic::VCVT_F64_U32_FIXED
                | Mnemonic::VCVT_S32_F64_FIXED
                | Mnemonic::VCVT_U32_F64_FIXED
                | Mnemonic::VCVTA_S32_F32
                | Mnemonic::VCVTA_U32_F32
                | Mnemonic::VCVTA_S32_F16
                | Mnemonic::VCVTA_U32_F16
                | Mnemonic::VCVTA_S32_F64
                | Mnemonic::VCVTA_U32_F64
                | Mnemonic::VCVTM_S32_F32
                | Mnemonic::VCVTM_U32_F32
                | Mnemonic::VCVTM_S32_F16
                | Mnemonic::VCVTM_U32_F16
                | Mnemonic::VCVTM_S32_F64
                | Mnemonic::VCVTM_U32_F64
                | Mnemonic::VCVTN_S32_F32
                | Mnemonic::VCVTN_U32_F32
                | Mnemonic::VCVTN_S32_F16
                | Mnemonic::VCVTN_U32_F16
                | Mnemonic::VCVTN_S32_F64
                | Mnemonic::VCVTN_U32_F64
                | Mnemonic::VCVTP_S32_F16
                | Mnemonic::VCVTP_U32_F16
                | Mnemonic::VCVTP_S32_F32
                | Mnemonic::VCVTP_U32_F32
                | Mnemonic::VCVTP_S32_F64
                | Mnemonic::VCVTP_U32_F64
                | Mnemonic::VCVTR_S32_F16
                | Mnemonic::VCVTR_U32_F16
                | Mnemonic::VCVTR_S32_F32
                | Mnemonic::VCVTR_U32_F32
                | Mnemonic::VCVTR_S32_F64
                | Mnemonic::VCVTR_U32_F64
                | Mnemonic::VMAX
                | Mnemonic::VMIN
                | Mnemonic::VLD1
                | Mnemonic::VLD2
                | Mnemonic::VLD3
                | Mnemonic::VLD4
                | Mnemonic::VST1
                | Mnemonic::VST2
                | Mnemonic::VST3
                | Mnemonic::VST4
                | Mnemonic::VLDR
                | Mnemonic::VSTR
                | Mnemonic::VLDM
                | Mnemonic::VSTM
                | Mnemonic::VPUSH
                | Mnemonic::VPOP
                | Mnemonic::VCVTB_F64_F16
                | Mnemonic::VCVTT_F64_F16
                | Mnemonic::VCVTB_F16_F64
                | Mnemonic::VCVTT_F16_F64
                | Mnemonic::VCVT_F16_S16
                | Mnemonic::VCVT_F16_U16
                | Mnemonic::VCVT_S16_F16
                | Mnemonic::VCVT_U16_F16
                | Mnemonic::VCVT_F16_S16_FIXED
                | Mnemonic::VCVT_S16_F16_FIXED
                | Mnemonic::VCVT_F16_U16_FIXED
                | Mnemonic::VCVT_U16_F16_FIXED
                | Mnemonic::VCVT_F16_S32_FIXED
                | Mnemonic::VCVT_S32_F16_FIXED
                | Mnemonic::VCVT_F16_U32_FIXED
                | Mnemonic::VCVT_U32_F16_FIXED
                | Mnemonic::VCVT_F32_S16_FIXED
                | Mnemonic::VCVT_S16_F32_FIXED
                | Mnemonic::VCVT_F32_U16_FIXED
                | Mnemonic::VCVT_U16_F32_FIXED
                | Mnemonic::VCVT_F64_S16_FIXED
                | Mnemonic::VCVT_S16_F64_FIXED
                | Mnemonic::VCVT_F64_U16_FIXED
                | Mnemonic::VCVT_U16_F64_FIXED
                | Mnemonic::VCVTA_S16_F16
                | Mnemonic::VCVTA_U16_F16
                | Mnemonic::VCVTN_S16_F16
                | Mnemonic::VCVTN_U16_F16
                | Mnemonic::VCVTP_S16_F16
                | Mnemonic::VCVTP_U16_F16
                | Mnemonic::VCVTM_S16_F16
                | Mnemonic::VCVTM_U16_F16
                | Mnemonic::VMOV_F16_CORE
                | Mnemonic::VMOVX_F16
                | Mnemonic::VINS_F16
        );
        if !fp_instruction && !fp_coprocessor {
            return false;
        }
        let raw = if insn.state.is_thumb() && insn.size == 4 {
            ThumbDecoder::a32_equivalent(insn.raw).unwrap_or(insn.raw)
        } else {
            insn.raw
        };
        // The implemented unconditional AdvSIMD data/structure spaces, plus
        // core VDUP and byte/halfword lane transfers. The 32-bit VMOV lane
        // transfer is VFP and deliberately does not depend on ASEDIS.
        let advsimd = matches!(raw >> 24, 0xf2 | 0xf3 | 0xf4)
            || matches!(
                insn.mnemonic,
                Mnemonic::VDUP | Mnemonic::VFMAL | Mnemonic::VFMLS
            )
            || (insn.mnemonic == Mnemonic::VMOV
                && raw & 0x0f00_0f10 == 0x0e00_0b10
                && raw & ((1 << 22) | (1 << 5)) != 0);
        if advsimd && self.cpu.cp15.cpacr.asedis() {
            return true;
        }
        // Arm AArch32.CheckAdvSIMDOrFPEnabled uses CPACR.cp10. The cp11
        // field is not a second access gate in the selected modern FP profile.
        // Reserved cp10=2 takes the permitted deny/Undefined policy.
        match self.cpu.cp15.cpacr.cp_access(10) {
            1 => !self.cpu.is_privileged(),
            3 => false,
            _ => true,
        }
    }
}

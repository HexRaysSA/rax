//! Arm XML 2025-12 FP access policy shared by standalone and mixed-width PEs.
use crate::isa::arm::decoder::{DecodedInsn, Mnemonic, ThumbDecoder};

#[derive(Clone, Copy, Debug)]
pub(crate) struct FpAccessKind {
    pub advsimd: bool,
    pub fpexc_check: bool,
    pub privileged_only: bool,
    pub invalid_system_encoding: bool,
    pub system_read: Option<u8>,
    pub raw: u32,
    pub condition: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FpAccessFault {
    /// Invalid encoding or an instruction whose system register is privileged.
    UndefinedEncoding,
    /// A valid FP instruction denied by its architectural access controls.
    Undefined,
    Trap {
        target_el: u8,
        syndrome: u32,
        undefined: bool,
    },
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct FpAccessContext {
    pub current_el: u8,
    pub secure: bool,
    pub have_el2: bool,
    pub have_el3: bool,
    pub el1_aarch64: bool,
    pub el2_aarch64: bool,
    pub el3_aarch64: bool,
    pub el2_enabled: bool,
    pub vhe: bool,
    pub cpacr: u32,
    pub fpexc: u32,
    pub nsacr: u32,
    pub hcptr: u32,
    pub hcr: u64,
    pub cptr_el2: u64,
    pub cptr_el3: u64,
}

impl FpAccessContext {
    pub(crate) fn effective_fpexc_enabled(self) -> bool {
        self.fpexc & (1 << 30) != 0
            || self.current_el == 0
                && (self.el1_aarch64
                    || self.el2_enabled && self.el2_aarch64 && self.hcr & (1 << 27) != 0)
    }

    fn trap(self, kind: FpAccessKind, target_el: u8, ec: u32, iss: u32) -> FpAccessFault {
        let condition = (1 << 24) | (u32::from(kind.condition) << 20);
        FpAccessFault::Trap {
            target_el,
            syndrome: (ec << 26) | (1 << 25) | condition | iss,
            undefined: self.current_el == 2 && target_el == 2 && !self.el2_aarch64,
        }
    }

    fn higher_aarch64_traps(self, kind: FpAccessKind) -> Option<FpAccessFault> {
        use crate::isa::arm::common::fp_access::FpAccessControls;
        let controls = FpAccessControls {
            current_el: self.current_el,
            el2_enabled: self.el2_enabled,
            have_el3: self.have_el3,
            vhe: self.vhe,
            hcr: self.hcr,
            cpacr: u64::from(self.cpacr),
            cptr_el2: self.cptr_el2,
            cptr_el3: self.cptr_el3,
        };
        controls
            .higher_fault()
            .map(|fault| self.trap(kind, fault.target_el, u32::from(fault.ec), 0))
    }

    pub(crate) fn check(self, kind: FpAccessKind) -> Option<FpAccessFault> {
        if kind.invalid_system_encoding || kind.privileged_only && self.current_el == 0 {
            return Some(FpAccessFault::UndefinedEncoding);
        }
        if self.current_el == 0 && self.el1_aarch64 {
            // FPEXC.EN is effectively one for A32 EL0 under an A64 EL1.
            let host = self.el2_enabled
                && self.vhe
                && self.hcr & (1 << 34) != 0
                && self.hcr & (1 << 27) != 0;
            if !host && (self.cpacr >> 20) & 3 != 3 {
                let target = if self.el2_enabled && self.hcr & (1 << 27) != 0 {
                    2
                } else {
                    1
                };
                return Some(if target == 2 {
                    FpAccessFault::Trap {
                        target_el: 2,
                        syndrome: 1 << 25,
                        undefined: false,
                    }
                } else {
                    self.trap(kind, 1, 7, 0)
                });
            }
            if let Some(fault) = self.higher_aarch64_traps(kind) {
                return Some(fault);
            }
        } else {
            let ns_clamp = self.have_el3 && !self.el3_aarch64 && !self.secure;
            let cp10 = if ns_clamp && self.nsacr & (1 << 10) == 0 {
                0
            } else {
                (self.cpacr >> 20) & 3
            };
            let asedis = self.cpacr & (1 << 31) != 0 || ns_clamp && self.nsacr & (1 << 15) != 0;
            if self.current_el != 2
                && (kind.advsimd && asedis
                    || match cp10 {
                        1 => self.current_el == 0,
                        3 => false,
                        _ => true, // Reserved cp10=2 takes the permitted deny policy.
                    })
            {
                return Some(FpAccessFault::Undefined);
            }
            // This profile chooses effective EN=1 for the implementation-defined
            // EL0 {TGE,RW}={1,0} case, retaining the existing mixed-width choice.
            if kind.fpexc_check && !self.effective_fpexc_enabled() {
                return Some(FpAccessFault::Undefined);
            }
            if self.el2_enabled && self.el2_aarch64 {
                if let Some(fault) = self.higher_aarch64_traps(kind) {
                    return Some(fault);
                }
            } else {
                if self.have_el2 && !self.secure {
                    let tcp10 =
                        self.hcptr & (1 << 10) != 0 || ns_clamp && self.nsacr & (1 << 10) == 0;
                    let tase =
                        self.hcptr & (1 << 15) != 0 || ns_clamp && self.nsacr & (1 << 15) != 0;
                    if tcp10 || kind.advsimd && tase {
                        return Some(self.trap(kind, 2, 7, if kind.advsimd { 1 << 5 } else { 10 }));
                    }
                }
                if self.have_el3 && self.el3_aarch64 && self.cptr_el3 & (1 << 10) != 0 {
                    return Some(self.trap(kind, 3, 7, 0));
                }
            }
        }
        // VMRS ID-group traps follow the ordinary access checks.
        if self.current_el == 1 && self.el2_enabled {
            if let Some(register) = kind.system_read {
                let trap_id = register == 0 && self.hcr & (1 << 15) != 0
                    || matches!(register, 5..=7) && self.hcr & (1 << 18) != 0;
                if trap_id {
                    let rt = (kind.raw >> 12) & 15;
                    let iss = (7 << 14) | (u32::from(register) << 10) | (rt << 5) | 1;
                    return Some(self.trap(kind, 2, 8, iss));
                }
            }
        }
        None
    }
}

/// Decode the access class without performing data or memory operations.
pub(crate) fn fp_access_kind(insn: &DecodedInsn) -> Option<FpAccessKind> {
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
            | Mnemonic::VSHLL
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
        return None;
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
    let system = matches!(insn.mnemonic, Mnemonic::VMRS | Mnemonic::VMSR)
        || matches!(insn.mnemonic, Mnemonic::MRC | Mnemonic::MCR)
            && coprocessor == 10
            && (insn.raw >> 21) & 7 == 7;
    let read = matches!(insn.mnemonic, Mnemonic::VMRS | Mnemonic::MRC);
    let register = ((insn.raw >> 16) & 15) as u8;
    let rt = (insn.raw >> 12) & 15;
    let invalid_system_encoding = fp_coprocessor && !system
        || system
            && ((insn.raw >> 21) & 7 != 7
                || (if read {
                    !matches!(register, 0 | 1 | 5..=8) || rt == 15 && register != 1
                } else {
                    !matches!(register, 0 | 1 | 8) || rt == 15
                }));
    Some(FpAccessKind {
        advsimd,
        fpexc_check: !system || register == 1,
        privileged_only: system && register != 1,
        invalid_system_encoding,
        system_read: (system && read).then_some(register),
        raw: insn.raw,
        condition: insn.cond.map_or(14, |value| value as u8),
    })
}

impl super::cpu::Armv7Cpu {
    pub(crate) fn fp_control_context(&self) -> FpAccessContext {
        if let Some(context) = self.fp_access_context {
            return context;
        }
        let current_el = match super::cpu::ProcessorMode::from_bits(self.cpsr.mode) {
            Some(super::cpu::ProcessorMode::User) => 0,
            Some(super::cpu::ProcessorMode::Hyp) => 2,
            Some(super::cpu::ProcessorMode::Monitor) => 3,
            _ => 1,
        };
        let have_el2 = (self.cp15.id_pfr1 >> 12) & 15 != 0;
        let have_el3 = (self.cp15.id_pfr1 >> 4) & 15 != 0;
        let secure = have_el3 && self.is_secure();
        FpAccessContext {
            current_el,
            secure,
            have_el2,
            have_el3,
            el1_aarch64: false,
            el2_aarch64: false,
            el3_aarch64: false,
            el2_enabled: have_el2 && !secure,
            vhe: false,
            cpacr: self.cp15.cpacr.bits(),
            fpexc: self.vfp.fpexc,
            nsacr: self.cp15.nsacr,
            hcptr: self.cp15.hcptr,
            hcr: u64::from(self.cp15.hcr),
            cptr_el2: 0,
            cptr_el3: 0,
        }
    }
}

#[cfg(test)]
mod shared_policy_tests {
    use super::*;
    #[test]
    fn shared_vhe_higher_fp_rule_preserves_aarch32_data_priority() {
        let mut controls = FpAccessContext {
            current_el: 1,
            secure: false,
            have_el2: true,
            have_el3: true,
            el1_aarch64: false,
            el2_aarch64: true,
            el3_aarch64: true,
            el2_enabled: true,
            vhe: true,
            cpacr: 3 << 20,
            fpexc: 1 << 30,
            nsacr: 0,
            hcptr: 0,
            hcr: (1 << 34) | (1 << 27),
            cptr_el2: 1 << 20,
            cptr_el3: 0,
        };
        let kind = FpAccessKind {
            advsimd: true,
            fpexc_check: true,
            privileged_only: false,
            invalid_system_encoding: false,
            system_read: None,
            raw: 0,
            condition: 14,
        };
        assert_eq!(controls.check(kind), None);
        controls.cptr_el3 = 1 << 10;
        assert!(matches!(
            controls.check(kind),
            Some(FpAccessFault::Trap { target_el: 3, .. })
        ));
        controls.cptr_el2 = 0;
        assert!(matches!(
            controls.check(kind),
            Some(FpAccessFault::Trap { target_el: 2, .. })
        ));
    }
}

//! Shared conversion from architectural register storage to PAuth execution state.

use super::pauth::{PauthConfig, PauthControls, PauthKey, PauthKeys};
use super::pauth_execution::PauthEnvironment;
use super::sysregs::SystemRegisters;
use crate::isa::arm::common::features::ArmFeatures;

impl PauthKeys {
    pub fn from_system_registers(sysregs: &SystemRegisters) -> Self {
        PauthKeys {
            ia: PauthKey {
                lo: sysregs.apiakeylo_el1,
                hi: sysregs.apiakeyhi_el1,
            },
            ib: PauthKey {
                lo: sysregs.apibkeylo_el1,
                hi: sysregs.apibkeyhi_el1,
            },
            da: PauthKey {
                lo: sysregs.apdakeylo_el1,
                hi: sysregs.apdakeyhi_el1,
            },
            db: PauthKey {
                lo: sysregs.apdbkeylo_el1,
                hi: sysregs.apdbkeyhi_el1,
            },
            ga: PauthKey {
                lo: sysregs.apgakeylo_el1,
                hi: sysregs.apgakeyhi_el1,
            },
        }
    }
}

impl PauthEnvironment {
    pub fn from_system_registers(
        features: ArmFeatures,
        config: PauthConfig,
        current_el: u8,
        sysregs: &SystemRegisters,
    ) -> Self {
        fn controls(
            features: ArmFeatures,
            current_el: u8,
            sysregs: &SystemRegisters,
        ) -> PauthControls {
            let mut implemented_els = 3; // EL0 and EL1 are mandatory.
            for el in 2..4 {
                if matches!((sysregs.id_aa64pfr0_el1 >> (el * 4)) & 15, 1 | 2) {
                    implemented_els |= 1 << el;
                }
            }
            PauthControls {
                current_el: current_el,
                implemented_els,
                secure_el2: features.contains(ArmFeatures::SEL2),
                vhe: features.contains(ArmFeatures::VHE),
                sctlr: [0, sysregs.el1.sctlr, sysregs.el2.sctlr, sysregs.el3.sctlr],
                tcr: [0, sysregs.el1.tcr, sysregs.el2.tcr, sysregs.el3.tcr],
                hcr_el2: sysregs.hcr_el2,
                scr_el3: sysregs.scr_el3,
            }
        }
        Self {
            features,
            config,
            controls: controls(features, current_el, sysregs),
            keys: PauthKeys::from_system_registers(sysregs),
        }
    }
}

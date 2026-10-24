//! Trusted host configuration of the AArch64 pointer-authentication model.

use crate::arch::RaxArch;
use crate::engine::{Engine, engine_mut, engine_ref};
use crate::{RaxStatus, guard};
use rax_engine::isa::arm::aarch64::pauth::{PauthAlgorithm, PauthConfig, PauthProfile};
use rax_engine::isa::arm::common::features::ArmFeatures;
use rax_engine::vm::vcpu::CpuState;

/// ABI 1.15 configuration. Its `size` includes the complete 32-byte prefix.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RaxArm64PauthConfig {
    pub size: u32,
    pub features: u32,
    pub algorithm: u32,
    pub profile: u32,
    pub reserved: [u32; 4],
}

fn decode(config: RaxArm64PauthConfig) -> Option<(ArmFeatures, PauthConfig)> {
    if config.features & !3 != 0 || config.reserved != [0; 4] {
        return None;
    }
    let algorithm = match config.algorithm {
        0 | 2 => PauthAlgorithm::Qarma5,
        1 => PauthAlgorithm::Qarma3,
        _ => return None,
    };
    let profile = match config.profile {
        0 | 4 => PauthProfile::FpacCombine,
        1 => PauthProfile::Base,
        2 => PauthProfile::Pauth2,
        3 => PauthProfile::Fpac,
        _ => return None,
    };
    let mut features = ArmFeatures::empty();
    features.set(ArmFeatures::PACA, config.features & 1 != 0);
    features.set(ArmFeatures::PACG, config.features & 2 != 0);
    Some((features, PauthConfig { algorithm, profile }))
}

#[unsafe(no_mangle)]
pub extern "C" fn rax_arm64_pauth_configure(
    engine: *mut Engine,
    config: *const RaxArm64PauthConfig,
) -> RaxStatus {
    guard(|| {
        let Some(engine) = (unsafe { engine_mut(engine) }) else {
            return RaxStatus::Handle;
        };
        engine.clear_err();
        if engine.arch != RaxArch::Arm64 {
            return engine.fail(RaxStatus::Arch, "PAuth configuration requires AArch64");
        }
        if engine.running {
            return engine.fail(RaxStatus::State, "cannot configure PAuth while running");
        }
        if config.is_null() || unsafe { core::ptr::read_unaligned(config.cast::<u32>()) } < 32 {
            return engine.fail(
                RaxStatus::Arg,
                "PAuth configuration requires a 32-byte prefix",
            );
        }
        let Some((features, pauth)) = decode(unsafe { core::ptr::read_unaligned(config) }) else {
            return engine.fail(RaxStatus::Arg, "invalid PAuth configuration");
        };
        let mut state = match engine.vcpu.get_state() {
            Ok(state) => state,
            Err(error) => return engine.fail_engine(&error),
        };
        let CpuState::Aarch64(arm) = &mut state else {
            return RaxStatus::Arch;
        };
        let Some(execution) = &mut arm.sregs.execution else {
            return RaxStatus::Reg;
        };
        let mask = (ArmFeatures::PACA | ArmFeatures::PACG).bits();
        execution.features = (execution.features & !mask) | features.bits();
        execution.pauth = pauth;
        match engine.vcpu.update_state(&state) {
            Ok(()) => RaxStatus::Ok,
            Err(error) => engine.fail_engine(&error),
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rax_arm64_pauth_get_config(
    engine: *const Engine,
    config: *mut RaxArm64PauthConfig,
) -> RaxStatus {
    guard(|| {
        let Some(engine) = (unsafe { engine_ref(engine) }) else {
            return RaxStatus::Handle;
        };
        if engine.arch != RaxArch::Arm64 {
            return RaxStatus::Arch;
        }
        if config.is_null() {
            return RaxStatus::Arg;
        }
        let size = unsafe { core::ptr::read_unaligned(config.cast::<u32>()) };
        if size < 32 {
            return RaxStatus::Arg;
        }
        let state = match engine.vcpu.get_state() {
            Ok(state) => state,
            Err(error) => return crate::status::status_from_engine_error(&error),
        };
        let CpuState::Aarch64(arm) = state else {
            return RaxStatus::Arch;
        };
        let Some(execution) = arm.sregs.execution else {
            return RaxStatus::Reg;
        };
        let features = u32::from(execution.features & ArmFeatures::PACA.bits() != 0)
            | (u32::from(execution.features & ArmFeatures::PACG.bits() != 0) << 1);
        let result = RaxArm64PauthConfig {
            size,
            features,
            algorithm: match execution.pauth.algorithm {
                PauthAlgorithm::Qarma3 => 1,
                PauthAlgorithm::Qarma5 => 2,
            },
            profile: match execution.pauth.profile {
                PauthProfile::Base => 1,
                PauthProfile::Pauth2 => 2,
                PauthProfile::Fpac => 3,
                PauthProfile::FpacCombine => 4,
            },
            reserved: [0; 4],
        };
        unsafe {
            core::ptr::write_unaligned(config, result);
        }
        RaxStatus::Ok
    })
}

/// Reset preserves the selected virtual-PE features/algorithm/profile while
/// resetting keys, enables, and every architectural register through the CPU.
pub(crate) fn inherit_configuration(source: &CpuState, target: &mut CpuState) {
    if let (CpuState::Aarch64(source), CpuState::Aarch64(target)) = (source, target) {
        if let (Some(source), Some(target)) = (&source.sregs.execution, &mut target.sregs.execution)
        {
            let mask = (ArmFeatures::PACA | ArmFeatures::PACG).bits();
            target.features = (target.features & !mask) | (source.features & mask);
            target.pauth = source.pauth;
        }
    }
}

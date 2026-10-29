//! Host selection of the software AArch64 optional FP/AdvSIMD profile.

use crate::arch::RaxArch;
use crate::engine::{Engine, engine_mut, engine_ref};
use crate::{RaxStatus, guard};
use rax_engine::isa::arm::common::features::ArmFeatures;

pub const RAX_ARM64_FEATURE_FP16: u32 = 1 << 0;
pub const RAX_ARM64_FEATURE_FHM: u32 = 1 << 1;
pub const RAX_ARM64_FEATURE_JSCVT: u32 = 1 << 2;
pub const RAX_ARM64_FEATURE_FCMA: u32 = 1 << 3;
pub const RAX_ARM64_FEATURE_FRINTTS: u32 = 1 << 4;
pub const RAX_ARM64_FEATURE_BF16: u32 = 1 << 5;
pub const RAX_ARM64_FEATURE_I8MM: u32 = 1 << 6;
pub const RAX_ARM64_FEATURE_DOTPROD: u32 = 1 << 7;
pub const RAX_ARM64_FP_FEATURES_SUPPORTED: u32 = 0xff;

const FEATURES: [(u32, ArmFeatures); 8] = [
    (RAX_ARM64_FEATURE_FP16, ArmFeatures::FP16),
    (RAX_ARM64_FEATURE_FHM, ArmFeatures::FHM),
    (RAX_ARM64_FEATURE_JSCVT, ArmFeatures::JSCVT),
    (RAX_ARM64_FEATURE_FCMA, ArmFeatures::FCMA),
    (RAX_ARM64_FEATURE_FRINTTS, ArmFeatures::FRINTTS),
    (RAX_ARM64_FEATURE_BF16, ArmFeatures::BF16),
    (RAX_ARM64_FEATURE_I8MM, ArmFeatures::I8MM),
    (RAX_ARM64_FEATURE_DOTPROD, ArmFeatures::DOTPROD),
];

/// ABI 1.16 configuration; callers provide at least this 32-byte prefix.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RaxArm64FpConfig {
    pub size: u32,
    pub features: u32,
    pub reserved: [u32; 6],
}

fn decode(config: RaxArm64FpConfig) -> Option<ArmFeatures> {
    if config.features & !RAX_ARM64_FP_FEATURES_SUPPORTED != 0 || config.reserved != [0; 6] {
        return None;
    }
    if config.features & RAX_ARM64_FEATURE_FHM != 0 && config.features & RAX_ARM64_FEATURE_FP16 == 0
    {
        return None;
    }
    let mut features = ArmFeatures::empty();
    for (public, internal) in FEATURES {
        features.set(internal, config.features & public != 0);
    }
    Some(features)
}

#[unsafe(no_mangle)]
pub extern "C" fn rax_arm64_fp_configure(
    engine: *mut Engine,
    config: *const RaxArm64FpConfig,
) -> RaxStatus {
    guard(|| {
        // SAFETY: the ABI requires a live, exclusively accessed handle or null;
        // engine_mut checks null and the handle magic before further access.
        let Some(engine) = (unsafe { engine_mut(engine) }) else {
            return RaxStatus::Handle;
        };
        engine.clear_err();
        if engine.arch != RaxArch::Arm64 {
            return engine.fail(RaxStatus::Arch, "FP/SIMD configuration requires AArch64");
        }
        if engine.running {
            return engine.fail(
                RaxStatus::State,
                "cannot configure FP/SIMD features while running",
            );
        }
        if config.is_null() {
            return engine.fail(
                RaxStatus::Arg,
                "FP/SIMD configuration requires a 32-byte prefix",
            );
        }
        // SAFETY: a nonnull configuration pointer must expose its readable size
        // word under the ABI contract. Unaligned configuration buffers are allowed.
        let size = unsafe { core::ptr::read_unaligned(config.cast::<u32>()) };
        if size < 32 {
            return engine.fail(
                RaxStatus::Arg,
                "FP/SIMD configuration requires a 32-byte prefix",
            );
        }
        // SAFETY: size admits the readable 32-byte prefix required from callers.
        // Reading the fixed prefix does not inspect a future caller-owned tail.
        let Some(features) = decode(unsafe { core::ptr::read_unaligned(config) }) else {
            return engine.fail(
                RaxStatus::Arg,
                "invalid FP/SIMD feature selection or reserved fields",
            );
        };
        match engine.vcpu.set_aarch64_fp_features(features.bits()) {
            Ok(()) => RaxStatus::Ok,
            Err(error) => engine.fail_engine(&error),
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn rax_arm64_fp_get_config(
    engine: *const Engine,
    config: *mut RaxArm64FpConfig,
) -> RaxStatus {
    guard(|| {
        // SAFETY: the ABI requires a live handle or null with no concurrent
        // mutation; engine_ref validates null and the handle magic.
        let Some(engine) = (unsafe { engine_ref(engine) }) else {
            return RaxStatus::Handle;
        };
        if engine.arch != RaxArch::Arm64 {
            return RaxStatus::Arch;
        }
        if engine.running {
            return RaxStatus::State;
        }
        if config.is_null() {
            return RaxStatus::Arg;
        }
        // SAFETY: callers provide a readable size word in a writable ABI buffer.
        let size = unsafe { core::ptr::read_unaligned(config.cast::<u32>()) };
        if size < 32 {
            return RaxStatus::Arg;
        }
        let Some(selected) = engine.vcpu.aarch64_fp_features() else {
            return RaxStatus::Arch;
        };
        let features = FEATURES.iter().fold(0, |flags, &(public, internal)| {
            flags
                | if selected & internal.bits() != 0 {
                    public
                } else {
                    0
                }
        });
        let result = RaxArm64FpConfig {
            size,
            features,
            reserved: [0; 6],
        };
        // SAFETY: the validated caller-owned buffer provides this writable
        // prefix. Unaligned writes preserve any bytes beyond its 32-byte prefix.
        unsafe {
            core::ptr::write_unaligned(config, result);
        }
        RaxStatus::Ok
    })
}

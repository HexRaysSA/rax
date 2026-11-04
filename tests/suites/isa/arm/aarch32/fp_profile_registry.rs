#[path = "fp_profile_decoded.rs"]
mod fp_profile_decoded;

#[cfg(all(target_arch = "aarch64", target_feature = "fp16"))]
#[path = "fp_profile_native.rs"]
mod fp_profile_native;

#[path = "fp_profile_matrix.rs"]
mod fp_profile_matrix;

#[path = "fp_nontrapping_profile.rs"]
mod fp_nontrapping_profile;

#[path = "fp_half_register.rs"]
mod fp_half_register;

#[path = "fp_vsel_apsr.rs"]
mod fp_vsel_apsr;

#[cfg(all(target_arch = "aarch64", target_feature = "fp16"))]
#[path = "fp_vsel_native.rs"]
mod fp_vsel_native;

#[path = "fp_system_registers.rs"]
mod fp_system_registers;

#[path = "fp_feature_registers.rs"]
mod fp_feature_registers;

#[path = "fp_access.rs"]
mod fp_access;

#[path = "fp_simd_access.rs"]
mod fp_simd_access;

#[path = "fp_short_vector_contract.rs"]
mod fp_short_vector_contract;

#[path = "fp_trapping_profile.rs"]
mod fp_trapping_profile;

#[path = "fp_core_transfer_admission.rs"]
mod fp_core_transfer_admission;

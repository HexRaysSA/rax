//! NEON / VFP SIMD instruction execution

use crate::isa::arm::ExecutionState;
use crate::isa::arm::aarch32::cpu::{
    ArmMemory, Armv7Cpu, MemoryError, ProcessorMode, Psr, add_with_carry, compute_n_flag,
    compute_z_flag, condition_passed, expand_imm_c, shift_c, sign_extend,
};
use crate::isa::arm::aarch32::instructions::*;
use crate::isa::arm::aarch32::vfp::{
    Fpscr, NeonSize, RoundingMode, vabs_f16_bits, vabs_f32, vabs_f64, vadd_f16_bits, vadd_f32,
    vadd_f64, vadd_i, vand, vbic, vcls_i, vclz_i, vcmp_f16_bits_with_exception,
    vcmp_f32_with_exception, vcmp_f64_with_exception, vcnt_i8, vcvt_f16_bits_f32,
    vcvt_f32_f16_bits, vcvt_f32_f64, vcvt_f32_s32, vcvt_f32_s32_fixed, vcvt_f32_u32,
    vcvt_f32_u32_fixed, vcvt_f64_f32, vcvt_f64_s32, vcvt_f64_s32_fixed, vcvt_f64_u32,
    vcvt_f64_u32_fixed, vcvt_s32_f32, vcvt_s32_f32_fixed, vcvt_s32_f32_round, vcvt_s32_f64,
    vcvt_s32_f64_fixed, vcvt_s32_f64_round, vcvt_u32_f32, vcvt_u32_f32_fixed, vcvt_u32_f32_round,
    vcvt_u32_f64, vcvt_u32_f64_fixed, vcvt_u32_f64_round, vcvtr_s32_f32, vcvtr_s32_f64,
    vcvtr_u32_f32, vcvtr_u32_f64, vdiv_f16_bits, vdiv_f32, vdiv_f64, veor, vfma_f16_bits, vfma_f32,
    vfma_f64, vfms_f16_bits, vfms_f32, vfms_f64, vfnma_f16_bits, vfnma_f32, vfnma_f64,
    vfnms_f16_bits, vfnms_f32, vfnms_f64, vfp_expand_imm_f16, vfp_expand_imm_f32,
    vfp_expand_imm_f64, vmaxnm_f16_bits, vmaxnm_f32, vmaxnm_f64, vminnm_f16_bits, vminnm_f32,
    vminnm_f64, vmla_f16_bits, vmla_f32, vmla_f64, vmls_f16_bits, vmls_f32, vmls_f64,
    vmul_f16_bits, vmul_f32, vmul_f64, vmvn, vneg_f16_bits, vneg_f32, vneg_f64, vnmla_f16_bits,
    vnmla_f32, vnmla_f64, vnmls_f16_bits, vnmls_f32, vnmls_f64, vnmul_f16_bits, vnmul_f32,
    vnmul_f64, vorn, vorr, vrev, vrint_f16_bits, vrint_f32, vrint_f64, vsqrt_f16_bits, vsqrt_f32,
    vsqrt_f64, vsub_f16_bits, vsub_f32, vsub_f64, vsub_i,
};
use crate::isa::arm::decoder::{Condition, DecodeError, DecodedInsn, Mnemonic, ShiftType};

// ---- module tree (auto-split) ----
mod fp;
pub(crate) use fp::*;
mod helpers;
pub(crate) use helpers::*;
mod memory;
pub(crate) use memory::*;
mod ops;
pub(crate) use ops::*;
mod shift;
pub(crate) use shift::*;

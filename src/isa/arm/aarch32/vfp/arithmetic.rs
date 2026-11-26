//! Scalar VFP arithmetic and exact guest-controlled binary16/binary32/binary64 results.
use super::Fpscr;
use crate::smir::interpret::{ArmFpOperation, SmirInterpreter};

pub(super) fn arithmetic_f32(
    operation: ArmFpOperation,
    first: f32,
    second: f32,
    fpscr: &mut Fpscr,
    negate_result: bool,
) -> f32 {
    let first = u64::from(fpscr.arithmetic_input_f32(first));
    let second = u64::from(fpscr.arithmetic_input_f32(second));
    let (bits, status) =
        SmirInterpreter::arm_eval_arithmetic(operation, first, second, false, fpscr.bits());
    let sign = u64::from(negate_result) << 31;
    f32::from_bits(fpscr.arithmetic_result(bits ^ sign, status) as u32)
}

pub(super) fn arithmetic_f64(
    operation: ArmFpOperation,
    first: f64,
    second: f64,
    fpscr: &mut Fpscr,
    negate_result: bool,
) -> f64 {
    let first = fpscr.arithmetic_input_f64(first);
    let second = fpscr.arithmetic_input_f64(second);
    let (bits, status) =
        SmirInterpreter::arm_eval_arithmetic(operation, first, second, true, fpscr.bits());
    let sign = u64::from(negate_result) << 63;
    f64::from_bits(fpscr.arithmetic_result(bits ^ sign, status))
}

/// Execute single-precision addition.
pub fn vadd_f32(a: f32, b: f32, fpscr: &mut Fpscr) -> f32 {
    arithmetic_f32(ArmFpOperation::Add, a, b, fpscr, false)
}

/// Execute double-precision addition.
pub fn vadd_f64(a: f64, b: f64, fpscr: &mut Fpscr) -> f64 {
    arithmetic_f64(ArmFpOperation::Add, a, b, fpscr, false)
}

/// Execute half-precision addition.
pub fn vadd_f16_bits(a: u16, b: u16, fpscr: &mut Fpscr) -> u16 {
    super::half::arithmetic(ArmFpOperation::Add, a, b, fpscr)
}

/// Execute single-precision subtraction.
pub fn vsub_f32(a: f32, b: f32, fpscr: &mut Fpscr) -> f32 {
    arithmetic_f32(ArmFpOperation::Subtract, a, b, fpscr, false)
}

/// Execute double-precision subtraction.
pub fn vsub_f64(a: f64, b: f64, fpscr: &mut Fpscr) -> f64 {
    arithmetic_f64(ArmFpOperation::Subtract, a, b, fpscr, false)
}

/// Execute half-precision subtraction.
pub fn vsub_f16_bits(a: u16, b: u16, fpscr: &mut Fpscr) -> u16 {
    super::half::arithmetic(ArmFpOperation::Subtract, a, b, fpscr)
}

/// Execute single-precision multiplication.
pub fn vmul_f32(a: f32, b: f32, fpscr: &mut Fpscr) -> f32 {
    arithmetic_f32(ArmFpOperation::Multiply, a, b, fpscr, false)
}

/// Execute double-precision multiplication.
pub fn vmul_f64(a: f64, b: f64, fpscr: &mut Fpscr) -> f64 {
    arithmetic_f64(ArmFpOperation::Multiply, a, b, fpscr, false)
}

/// Execute half-precision multiplication.
pub fn vmul_f16_bits(a: u16, b: u16, fpscr: &mut Fpscr) -> u16 {
    super::half::arithmetic(ArmFpOperation::Multiply, a, b, fpscr)
}

/// Execute single-precision division.
pub fn vdiv_f32(a: f32, b: f32, fpscr: &mut Fpscr) -> f32 {
    arithmetic_f32(ArmFpOperation::Divide, a, b, fpscr, false)
}

/// Execute double-precision division.
pub fn vdiv_f64(a: f64, b: f64, fpscr: &mut Fpscr) -> f64 {
    arithmetic_f64(ArmFpOperation::Divide, a, b, fpscr, false)
}

/// Execute half-precision division.
pub fn vdiv_f16_bits(a: u16, b: u16, fpscr: &mut Fpscr) -> u16 {
    super::half::arithmetic(ArmFpOperation::Divide, a, b, fpscr)
}

/// Execute single-precision negation.
pub fn vneg_f32(a: f32) -> f32 {
    f32::from_bits(a.to_bits() ^ (1 << 31))
}

/// Execute double-precision negation.
pub fn vneg_f64(a: f64) -> f64 {
    f64::from_bits(a.to_bits() ^ (1 << 63))
}

/// Execute half-precision negation.
pub fn vneg_f16_bits(a: u16) -> u16 {
    a ^ 0x8000
}

/// Execute single-precision absolute value.
pub fn vabs_f32(a: f32) -> f32 {
    a.abs()
}

/// Execute double-precision absolute value.
pub fn vabs_f64(a: f64) -> f64 {
    a.abs()
}

/// Execute half-precision absolute value.
pub fn vabs_f16_bits(a: u16) -> u16 {
    a & 0x7FFF
}

/// Execute single-precision square root.
pub fn vsqrt_f32(a: f32, fpscr: &mut Fpscr) -> f32 {
    arithmetic_f32(ArmFpOperation::SquareRoot, a, 0.0, fpscr, false)
}

/// Execute double-precision square root.
pub fn vsqrt_f64(a: f64, fpscr: &mut Fpscr) -> f64 {
    arithmetic_f64(ArmFpOperation::SquareRoot, a, 0.0, fpscr, false)
}

/// Execute half-precision square root.
pub fn vsqrt_f16_bits(a: u16, fpscr: &mut Fpscr) -> u16 {
    super::half::arithmetic(ArmFpOperation::SquareRoot, a, 0, fpscr)
}

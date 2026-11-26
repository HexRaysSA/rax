//! Scalar VFP arithmetic and exact guest-controlled binary16/binary32/binary64 results.
use super::Fpscr;
use crate::smir::interpret::{ArmFpOperation, SmirInterpreter};

pub(super) enum ResultSign {
    Preserve,
    Negate,
    NegateRoundedProduct,
}

impl ResultSign {
    fn apply(
        self,
        fpscr: &mut Fpscr,
        bits: u64,
        status: u32,
        sign: u64,
        canonical_nan: u64,
    ) -> u64 {
        // DDI 0301H §22.6.2 specifies Default NaN for an invalid product
        // even with DN clear. Only use the current operation's IOC.
        let default_nan = fpscr.arm11 && bits == canonical_nan && (fpscr.dn() || status & 1 != 0);
        match self {
            Self::Negate if !default_nan => fpscr.arithmetic_result(bits ^ sign, status),
            Self::NegateRoundedProduct if !default_nan => {
                // The multiply stage flushes before its product becomes a
                // signed addend. The accumulator stage observes that sign.
                fpscr.arithmetic_result(bits, status) ^ sign
            }
            _ => fpscr.arithmetic_result(bits, status),
        }
    }
}

pub(super) fn arithmetic_f32(
    operation: ArmFpOperation,
    first: f32,
    second: f32,
    fpscr: &mut Fpscr,
    sign: ResultSign,
) -> f32 {
    let first = u64::from(fpscr.arithmetic_input_f32(first));
    let second = u64::from(fpscr.arithmetic_input_f32(second));
    let (bits, status) =
        SmirInterpreter::arm_eval_arithmetic(operation, first, second, false, fpscr.bits());
    f32::from_bits(sign.apply(fpscr, bits, status, 1 << 31, 0x7fc0_0000) as u32)
}

pub(super) fn arithmetic_f64(
    operation: ArmFpOperation,
    first: f64,
    second: f64,
    fpscr: &mut Fpscr,
    sign: ResultSign,
) -> f64 {
    let first = fpscr.arithmetic_input_f64(first);
    let second = fpscr.arithmetic_input_f64(second);
    let (bits, status) =
        SmirInterpreter::arm_eval_arithmetic(operation, first, second, true, fpscr.bits());
    f64::from_bits(sign.apply(fpscr, bits, status, 1 << 63, 0x7ff8_0000_0000_0000))
}

/// Execute single-precision addition.
pub fn vadd_f32(a: f32, b: f32, fpscr: &mut Fpscr) -> f32 {
    arithmetic_f32(ArmFpOperation::Add, a, b, fpscr, ResultSign::Preserve)
}

/// Execute double-precision addition.
pub fn vadd_f64(a: f64, b: f64, fpscr: &mut Fpscr) -> f64 {
    arithmetic_f64(ArmFpOperation::Add, a, b, fpscr, ResultSign::Preserve)
}

/// Execute half-precision addition.
pub fn vadd_f16_bits(a: u16, b: u16, fpscr: &mut Fpscr) -> u16 {
    super::half::arithmetic(ArmFpOperation::Add, a, b, fpscr)
}

/// Execute single-precision subtraction.
pub fn vsub_f32(a: f32, b: f32, fpscr: &mut Fpscr) -> f32 {
    arithmetic_f32(ArmFpOperation::Subtract, a, b, fpscr, ResultSign::Preserve)
}

/// Execute double-precision subtraction.
pub fn vsub_f64(a: f64, b: f64, fpscr: &mut Fpscr) -> f64 {
    arithmetic_f64(ArmFpOperation::Subtract, a, b, fpscr, ResultSign::Preserve)
}

/// Execute half-precision subtraction.
pub fn vsub_f16_bits(a: u16, b: u16, fpscr: &mut Fpscr) -> u16 {
    super::half::arithmetic(ArmFpOperation::Subtract, a, b, fpscr)
}

/// Execute single-precision multiplication.
pub fn vmul_f32(a: f32, b: f32, fpscr: &mut Fpscr) -> f32 {
    arithmetic_f32(ArmFpOperation::Multiply, a, b, fpscr, ResultSign::Preserve)
}

/// Execute double-precision multiplication.
pub fn vmul_f64(a: f64, b: f64, fpscr: &mut Fpscr) -> f64 {
    arithmetic_f64(ArmFpOperation::Multiply, a, b, fpscr, ResultSign::Preserve)
}

/// Execute half-precision multiplication.
pub fn vmul_f16_bits(a: u16, b: u16, fpscr: &mut Fpscr) -> u16 {
    super::half::arithmetic(ArmFpOperation::Multiply, a, b, fpscr)
}

/// Execute single-precision division.
pub fn vdiv_f32(a: f32, b: f32, fpscr: &mut Fpscr) -> f32 {
    arithmetic_f32(ArmFpOperation::Divide, a, b, fpscr, ResultSign::Preserve)
}

/// Execute double-precision division.
pub fn vdiv_f64(a: f64, b: f64, fpscr: &mut Fpscr) -> f64 {
    arithmetic_f64(ArmFpOperation::Divide, a, b, fpscr, ResultSign::Preserve)
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
    arithmetic_f32(
        ArmFpOperation::SquareRoot,
        a,
        0.0,
        fpscr,
        ResultSign::Preserve,
    )
}

/// Execute double-precision square root.
pub fn vsqrt_f64(a: f64, fpscr: &mut Fpscr) -> f64 {
    arithmetic_f64(
        ArmFpOperation::SquareRoot,
        a,
        0.0,
        fpscr,
        ResultSign::Preserve,
    )
}

/// Execute half-precision square root.
pub fn vsqrt_f16_bits(a: u16, fpscr: &mut Fpscr) -> u16 {
    super::half::arithmetic(ArmFpOperation::SquareRoot, a, 0, fpscr)
}

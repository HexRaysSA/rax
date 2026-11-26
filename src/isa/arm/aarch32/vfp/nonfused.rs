//! Multiply then add/subtract: both arithmetic steps round under guest FPSCR.
use super::arithmetic::{arithmetic_f32, arithmetic_f64};
use super::{
    Fpscr, vadd_f16_bits, vadd_f32, vadd_f64, vmul_f16_bits, vmul_f32, vmul_f64, vneg_f32, vneg_f64,
};
use crate::smir::interpret::ArmFpOperation;

/// Execute single-precision multiply-accumulate.
pub fn vmla_f32(acc: f32, a: f32, b: f32, fpscr: &mut Fpscr) -> f32 {
    let product = vmul_f32(a, b, fpscr);
    vadd_f32(acc, product, fpscr)
}

/// Execute double-precision multiply-accumulate.
pub fn vmla_f64(acc: f64, a: f64, b: f64, fpscr: &mut Fpscr) -> f64 {
    let product = vmul_f64(a, b, fpscr);
    vadd_f64(acc, product, fpscr)
}

/// Execute half-precision multiply-accumulate.
pub fn vmla_f16_bits(acc: u16, a: u16, b: u16, fpscr: &mut Fpscr) -> u16 {
    let product = vmul_f16_bits(a, b, fpscr);
    vadd_f16_bits(acc, product, fpscr)
}

/// Execute single-precision multiply-subtract.
pub fn vmls_f32(acc: f32, a: f32, b: f32, fpscr: &mut Fpscr) -> f32 {
    let product = vmul_f32(a, b, fpscr);
    vadd_f32(acc, vneg_f32(product), fpscr)
}

/// Execute double-precision multiply-subtract.
pub fn vmls_f64(acc: f64, a: f64, b: f64, fpscr: &mut Fpscr) -> f64 {
    let product = vmul_f64(a, b, fpscr);
    vadd_f64(acc, vneg_f64(product), fpscr)
}

/// Execute half-precision multiply-subtract.
pub fn vmls_f16_bits(acc: u16, a: u16, b: u16, fpscr: &mut Fpscr) -> u16 {
    let product = vmul_f16_bits(a, b, fpscr);
    vadd_f16_bits(acc, product ^ 0x8000, fpscr)
}

/// Execute single-precision negated multiply-accumulate.
pub fn vnmla_f32(acc: f32, a: f32, b: f32, fpscr: &mut Fpscr) -> f32 {
    let product = vmul_f32(a, b, fpscr);
    vadd_f32(vneg_f32(acc), vneg_f32(product), fpscr)
}

/// Execute double-precision negated multiply-accumulate.
pub fn vnmla_f64(acc: f64, a: f64, b: f64, fpscr: &mut Fpscr) -> f64 {
    let product = vmul_f64(a, b, fpscr);
    vadd_f64(vneg_f64(acc), vneg_f64(product), fpscr)
}

/// Execute half-precision negated multiply-accumulate.
pub fn vnmla_f16_bits(acc: u16, a: u16, b: u16, fpscr: &mut Fpscr) -> u16 {
    let product = vmul_f16_bits(a, b, fpscr);
    vadd_f16_bits(acc ^ 0x8000, product ^ 0x8000, fpscr)
}

/// Execute single-precision negated multiply-subtract.
pub fn vnmls_f32(acc: f32, a: f32, b: f32, fpscr: &mut Fpscr) -> f32 {
    let product = vmul_f32(a, b, fpscr);
    vadd_f32(vneg_f32(acc), product, fpscr)
}

/// Execute double-precision negated multiply-subtract.
pub fn vnmls_f64(acc: f64, a: f64, b: f64, fpscr: &mut Fpscr) -> f64 {
    let product = vmul_f64(a, b, fpscr);
    vadd_f64(vneg_f64(acc), product, fpscr)
}

/// Execute half-precision negated multiply-subtract.
pub fn vnmls_f16_bits(acc: u16, a: u16, b: u16, fpscr: &mut Fpscr) -> u16 {
    let product = vmul_f16_bits(a, b, fpscr);
    vadd_f16_bits(acc ^ 0x8000, product, fpscr)
}

/// Execute single-precision negated multiply.
pub fn vnmul_f32(a: f32, b: f32, fpscr: &mut Fpscr) -> f32 {
    arithmetic_f32(ArmFpOperation::Multiply, a, b, fpscr, true)
}

/// Execute double-precision negated multiply.
pub fn vnmul_f64(a: f64, b: f64, fpscr: &mut Fpscr) -> f64 {
    arithmetic_f64(ArmFpOperation::Multiply, a, b, fpscr, true)
}

/// Execute half-precision negated multiply.
pub fn vnmul_f16_bits(a: u16, b: u16, fpscr: &mut Fpscr) -> u16 {
    vmul_f16_bits(a, b, fpscr) ^ 0x8000
}

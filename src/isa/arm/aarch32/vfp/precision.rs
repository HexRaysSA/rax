//! VFP binary32/binary64 precision changes with guest FPSCR semantics.
use super::Fpscr;
use crate::smir::interpret::SmirInterpreter;

/// Convert single to double using the default FPSCR controls. Call the
/// controlled variant when cumulative exceptions and guest controls matter.
pub fn vcvt_f64_f32(value: f32) -> f64 {
    vcvt_f64_f32_with_fpscr(value, &mut Fpscr::default())
}

/// Convert single to double with input flushing, NaN processing and sticky flags.
pub fn vcvt_f64_f32_with_fpscr(value: f32, fpscr: &mut Fpscr) -> f64 {
    let value = u64::from(fpscr.arithmetic_input_f32(value));
    let (bits, status) = SmirInterpreter::arm_eval_precision_conversion(value, true, fpscr.bits());
    f64::from_bits(fpscr.arithmetic_result(bits, status))
}

/// Convert double to single with guest rounding, flushing and sticky flags.
pub fn vcvt_f32_f64(value: f64, fpscr: &mut Fpscr) -> f32 {
    let value = fpscr.arithmetic_input_f64(value);
    let (bits, status) = SmirInterpreter::arm_eval_precision_conversion(value, false, fpscr.bits());
    f32::from_bits(fpscr.arithmetic_result(bits, status) as u32)
}

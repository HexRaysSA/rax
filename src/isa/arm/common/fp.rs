/// Arm FPToFixedJS integer result and Z flag. A flushed subnormal still
/// clears Z because its original fraction was nonzero. Callers apply their
/// profiles' different cumulative exception and trap controls.
pub(crate) fn js_to_int32(input: f64) -> (u32, bool) {
    if !input.is_finite() {
        return (0, false);
    }
    const MODULUS: f64 = 4294967296.0;
    let integer = input.trunc();
    let wrapped = integer.rem_euclid(MODULUS) as u32;
    let negative_zero = input.to_bits() == (-0.0_f64).to_bits();
    (
        wrapped,
        input == f64::from(wrapped as i32) && !negative_zero,
    )
}

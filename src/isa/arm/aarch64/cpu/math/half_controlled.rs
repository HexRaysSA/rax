// Guest-controlled half arithmetic, preserving the legacy AH-specific path.
pub(crate) fn sve_fp16_binop_with_fpcr(kind: FpKind, x: u16, y: u16, fpcr: u32) -> u16 {
    if let Some((result, _)) = super::fp::controlled_half_binary(kind, x, y, fpcr) {
        return result;
    }

    use FpKind::*;
    let (x, y) = if fpcr & FPCR_FZ16 != 0 {
        (
            fp16_flush_input_with_fpcr(x, fpcr),
            fp16_flush_input_with_fpcr(y, fpcr),
        )
    } else {
        (x, y)
    };
    if fpcr & FPCR_AH != 0 && matches!(kind, Max | Min) {
        if let Some(r) = fp16_ah_nan_number(x, y) {
            return r;
        }
    }
    if fpcr & FPCR_AH != 0 && matches!(kind, Add | Addp | Sub | Mul | Div | Mulx | Abd) {
        if let Some(n) = fp16_ah_nan2(x, y) {
            return n;
        }
    }
    let ah_invalid_default = |r| {
        if fp_invalid_binop_f16(kind, x, y) {
            fp_ah_invalid_default_nan(2, r as u64, fpcr) as u16
        } else {
            r
        }
    };
    if (fpcr >> 22) & 0x3 == 0 || fp16_is_nan(x) || fp16_is_nan(y) {
        return ah_invalid_default(sve_fp16_binop(kind, x, y));
    }
    let finite_pair = !fp16_is_inf(x) && !fp16_is_inf(y);
    let exact = match kind {
        Add | Addp if finite_pair => fp16_to_f64(x) + fp16_to_f64(y),
        Sub if finite_pair => fp16_to_f64(x) - fp16_to_f64(y),
        Mul if finite_pair => fp16_to_f64(x) * fp16_to_f64(y),
        Div if finite_pair && !fp16_is_zero(y) => fp16_to_f64(x) / fp16_to_f64(y),
        Abd if finite_pair => (fp16_to_f64(x) - fp16_to_f64(y)).abs(),
        _ => return ah_invalid_default(sve_fp16_binop(kind, x, y)),
    };
    if exact == 0.0
        && matches!(kind, Add | Addp | Sub)
        && fp_addsub_cancelled_zero_rounds_negative(
            x as u64,
            y as u64,
            matches!(kind, Sub),
            16,
            fpcr,
        )
    {
        return 0x8000;
    }
    f64_to_fp16_bits_with_fpcr(exact, fpcr)
}

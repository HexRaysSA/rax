// Selected typed FPRound status producers and optional underflow collection.
// Included in fp.rs to preserve existing helper paths and private names.

pub(super) fn controlled_half_binary(
    kind: FpKind,
    x: u16,
    y: u16,
    fpcr: u32,
) -> Option<(u16, u32)> {
    use crate::smir::interpret::{ArmFpOperation, SmirInterpreter};
    if fpcr & FPCR_AH != 0 {
        return None;
    }
    let operation = match kind {
        FpKind::Add | FpKind::Addp => ArmFpOperation::Add,
        FpKind::Sub | FpKind::Abd => ArmFpOperation::Subtract,
        FpKind::Mul => ArmFpOperation::Multiply,
        FpKind::Mulx
            if !((fp16_is_zero(x) && fp16_is_inf(y)) || (fp16_is_inf(x) && fp16_is_zero(y))) =>
        {
            ArmFpOperation::Multiply
        }
        FpKind::Div => ArmFpOperation::Divide,
        _ => return None,
    };
    let (mut result, status) = SmirInterpreter::arm_eval_half_arithmetic(operation, x, y, fpcr);
    if matches!(kind, FpKind::Abd) {
        result &= 0x7fff;
    }
    Some((result, status))
}

fn fp_status_binop_with_fpcr_without_trap_collection(
    esize: usize,
    kind: FpKind,
    a: u64,
    b: u64,
    result: u64,
    fpcr: u32,
) -> u32 {
    if esize == 2 {
        if let Some((_, status)) = controlled_half_binary(kind, a as u16, b as u16, fpcr) {
            return status;
        }
    }
    if fpcr & FPCR_AH != 0 && (fp_is_nan_bits(esize, a) || fp_is_nan_bits(esize, b)) {
        if matches!(
            kind,
            FpKind::Max | FpKind::Maxp | FpKind::Min | FpKind::Minp
        ) {
            return FPSR_IOC;
        }
        return fp_status_binop(esize, kind, a, b, result);
    }
    if fp_input_flush_enabled(esize, fpcr)
        && matches!(
            kind,
            FpKind::Add
                | FpKind::Addp
                | FpKind::Sub
                | FpKind::Mul
                | FpKind::Div
                | FpKind::Abd
                | FpKind::Max
                | FpKind::Maxp
                | FpKind::MaxNm
                | FpKind::MaxNmp
                | FpKind::Min
                | FpKind::Minp
                | FpKind::MinNm
                | FpKind::MinNmp
        )
    {
        let fz_input_status =
            fp_fz_input_status(esize, a, fpcr) | fp_fz_input_status(esize, b, fpcr);
        match esize {
            2 => {
                return fp_status_binop_f16(
                    kind,
                    fp16_flush_input_with_fpcr(a as u16, fpcr),
                    fp16_flush_input_with_fpcr(b as u16, fpcr),
                    result as u16,
                );
            }
            4 => {
                let a = fp32_flush_input_with_fpcr(a as u32, fpcr);
                let b = fp32_flush_input_with_fpcr(b as u32, fpcr);
                let output = fp_fz_binop_output(esize, kind, a as u64, b as u64, result, fpcr);
                let status_result = output.map_or(result, |(raw, _)| raw);
                return fp_status_binop_f32(kind, a, b, status_result as u32)
                    | fz_input_status
                    | output.map_or(0, |(_, status)| status);
            }
            8 => {
                let a = fp64_flush_input_with_fpcr(a, fpcr);
                let b = fp64_flush_input_with_fpcr(b, fpcr);
                let output = fp_fz_binop_output(esize, kind, a, b, result, fpcr);
                let status_result = output.map_or(result, |(raw, _)| raw);
                return fp_status_binop_f64(kind, a, b, status_result)
                    | fz_input_status
                    | output.map_or(0, |(_, status)| status);
            }
            _ => {}
        }
    }
    fp_status_binop(esize, kind, a, b, result)
        | fp_fz_input_status(esize, a, fpcr)
        | fp_fz_input_status(esize, b, fpcr)
}

pub(crate) fn fp_status_binop_with_fpcr(
    esize: usize,
    kind: FpKind,
    a: u64,
    b: u64,
    result: u64,
    fpcr: u32,
) -> u32 {
    let status = fp_status_binop_with_fpcr_without_trap_collection(esize, kind, a, b, result, fpcr);
    crate::isa::arm::aarch64::cpu::fp_traps::collect_underflow(esize, result, status, fpcr)
}

fn fp_status_fma_with_fpcr_without_trap_collection(
    esize: usize,
    addend: u64,
    op1: u64,
    op2: u64,
    result: u64,
    fpcr: u32,
) -> u32 {
    if esize == 2 && fpcr & FPCR_AH == 0 {
        return crate::smir::interpret::SmirInterpreter::arm_eval_half_fused(
            addend as u16,
            op1 as u16,
            op2 as u16,
            fpcr,
        )
        .1;
    }
    if fpcr & FPCR_AH != 0
        && (fp_is_nan_bits(esize, addend)
            || fp_is_nan_bits(esize, op1)
            || fp_is_nan_bits(esize, op2))
    {
        return fp_status_fma(esize, addend, op1, op2, result);
    }
    if fp_input_flush_enabled(esize, fpcr) {
        let fz_input_status = fp_fz_input_status(esize, addend, fpcr)
            | fp_fz_input_status(esize, op1, fpcr)
            | fp_fz_input_status(esize, op2, fpcr);
        match esize {
            2 => {
                return fp_status_fma(
                    esize,
                    fp16_flush_input_with_fpcr(addend as u16, fpcr) as u64,
                    fp16_flush_input_with_fpcr(op1 as u16, fpcr) as u64,
                    fp16_flush_input_with_fpcr(op2 as u16, fpcr) as u64,
                    result,
                );
            }
            4 => {
                let addend = fp32_flush_input_with_fpcr(addend as u32, fpcr) as u64;
                let op1 = fp32_flush_input_with_fpcr(op1 as u32, fpcr) as u64;
                let op2 = fp32_flush_input_with_fpcr(op2 as u32, fpcr) as u64;
                let output = fp_fz_fma_output(esize, addend, op1, op2, result, fpcr);
                let status_result = output.map_or(result, |(raw, _)| raw);
                return fp_status_fma(esize, addend, op1, op2, status_result)
                    | fz_input_status
                    | output.map_or(0, |(_, status)| status);
            }
            8 => {
                let addend = fp64_flush_input_with_fpcr(addend, fpcr);
                let op1 = fp64_flush_input_with_fpcr(op1, fpcr);
                let op2 = fp64_flush_input_with_fpcr(op2, fpcr);
                let output = fp_fz_fma_output(esize, addend, op1, op2, result, fpcr);
                let status_result = output.map_or(result, |(raw, _)| raw);
                return fp_status_fma(esize, addend, op1, op2, status_result)
                    | fz_input_status
                    | output.map_or(0, |(_, status)| status);
            }
            _ => {}
        }
    }
    fp_status_fma(esize, addend, op1, op2, result)
        | fp_fz_input_status(esize, addend, fpcr)
        | fp_fz_input_status(esize, op1, fpcr)
        | fp_fz_input_status(esize, op2, fpcr)
}

pub(crate) fn fp_status_fma_with_fpcr(
    esize: usize,
    addend: u64,
    op1: u64,
    op2: u64,
    result: u64,
    fpcr: u32,
) -> u32 {
    let status =
        fp_status_fma_with_fpcr_without_trap_collection(esize, addend, op1, op2, result, fpcr);
    crate::isa::arm::aarch64::cpu::fp_traps::collect_underflow(esize, result, status, fpcr)
}

fn fp_status_mulx_with_fpcr_without_trap_collection(
    esize: usize,
    a: u64,
    b: u64,
    result: u64,
    fpcr: u32,
) -> u32 {
    let input_status = fp_fz_input_status(esize, a, fpcr) | fp_fz_input_status(esize, b, fpcr);
    if fp_input_flush_enabled(esize, fpcr) {
        match esize {
            2 => {
                return fp_status_mulx(
                    esize,
                    fp16_flush_input_with_fpcr(a as u16, fpcr) as u64,
                    fp16_flush_input_with_fpcr(b as u16, fpcr) as u64,
                    result,
                ) | input_status;
            }
            4 => {
                return fp_status_mulx(
                    esize,
                    fp32_flush_input_with_fpcr(a as u32, fpcr) as u64,
                    fp32_flush_input_with_fpcr(b as u32, fpcr) as u64,
                    result,
                ) | input_status;
            }
            8 => {
                return fp_status_mulx(
                    esize,
                    fp64_flush_input_with_fpcr(a, fpcr),
                    fp64_flush_input_with_fpcr(b, fpcr),
                    result,
                ) | input_status;
            }
            _ => {}
        }
    }
    fp_status_mulx(esize, a, b, result) | input_status
}

pub(crate) fn fp_status_mulx_with_fpcr(
    esize: usize,
    a: u64,
    b: u64,
    result: u64,
    fpcr: u32,
) -> u32 {
    let status = fp_status_mulx_with_fpcr_without_trap_collection(esize, a, b, result, fpcr);
    crate::isa::arm::aarch64::cpu::fp_traps::collect_underflow(esize, result, status, fpcr)
}

fn fp_status_recps_rsqrts_with_fpcr_without_trap_collection(
    esize: usize,
    rsqrt: bool,
    a: u64,
    b: u64,
    result: u64,
    fpcr: u32,
) -> u32 {
    if fpcr & FPCR_AH != 0 {
        return 0;
    }
    let input_status = fp_fz_input_status(esize, a, fpcr) | fp_fz_input_status(esize, b, fpcr);
    if fp_input_flush_enabled(esize, fpcr) {
        match esize {
            2 => {
                return fp_status_recps_rsqrts(
                    esize,
                    rsqrt,
                    fp16_flush_input_with_fpcr(a as u16, fpcr) as u64,
                    fp16_flush_input_with_fpcr(b as u16, fpcr) as u64,
                    result,
                ) | input_status;
            }
            4 => {
                return fp_status_recps_rsqrts(
                    esize,
                    rsqrt,
                    fp32_flush_input_with_fpcr(a as u32, fpcr) as u64,
                    fp32_flush_input_with_fpcr(b as u32, fpcr) as u64,
                    result,
                ) | input_status;
            }
            8 => {
                return fp_status_recps_rsqrts(
                    esize,
                    rsqrt,
                    fp64_flush_input_with_fpcr(a, fpcr),
                    fp64_flush_input_with_fpcr(b, fpcr),
                    result,
                ) | input_status;
            }
            _ => {}
        }
    }
    fp_status_recps_rsqrts(esize, rsqrt, a, b, result)
}

pub(crate) fn fp_status_recps_rsqrts_with_fpcr(
    esize: usize,
    rsqrt: bool,
    a: u64,
    b: u64,
    result: u64,
    fpcr: u32,
) -> u32 {
    let status =
        fp_status_recps_rsqrts_with_fpcr_without_trap_collection(esize, rsqrt, a, b, result, fpcr);
    crate::isa::arm::aarch64::cpu::fp_traps::collect_underflow(esize, result, status, fpcr)
}

fn fp_status_cvt_precision_with_fpcr_rounding_without_trap_collection(
    src: u64,
    src_prec: usize,
    dst_prec: usize,
    result: u64,
    round_odd: bool,
    fpcr: u32,
) -> u32 {
    let input_status = fp_fz_input_status(src_prec, src, fpcr);
    let src = fp_cvt_input_bits_with_fpcr(src, src_prec, dst_prec, fpcr);
    let output = fp_fz_cvt_output(src, src_prec, dst_prec, result, round_odd, fpcr);
    let status_result = output.map_or(result, |(raw, _)| raw);
    let mut status = fp_status_cvt_precision(src, src_prec, dst_prec, status_result);
    if round_odd && output.is_some() {
        status &= !FPSR_IXC;
    }
    status | input_status | output.map_or(0, |(_, status)| status)
}

pub(crate) fn fp_status_cvt_precision_with_fpcr_rounding(
    src: u64,
    src_prec: usize,
    dst_prec: usize,
    result: u64,
    round_odd: bool,
    fpcr: u32,
) -> u32 {
    let status = fp_status_cvt_precision_with_fpcr_rounding_without_trap_collection(
        src, src_prec, dst_prec, result, round_odd, fpcr,
    );
    crate::isa::arm::aarch64::cpu::fp_traps::collect_underflow(
        dst_prec,
        result,
        status,
        if dst_prec == 2 {
            fpcr & !FPCR_FZ16
        } else {
            fpcr
        },
    )
}

fn fp_status_sve_underflow_without_trap_collection(esize: usize, result: u64, status: u32) -> u32 {
    if status & FPSR_IXC == 0 {
        return status;
    }
    let underflow = match esize {
        2 => fp16_is_tiny(result as u16) || fp16_is_zero(result as u16),
        4 => fp32_is_tiny(result as u32) || fp32_is_zero(result as u32),
        _ => fp64_is_tiny(result) || fp64_is_zero(result),
    };
    status | if underflow { FPSR_UFC } else { 0 }
}

pub(crate) fn fp_status_sve_underflow(esize: usize, result: u64, status: u32) -> u32 {
    let status = fp_status_sve_underflow_without_trap_collection(esize, result, status);
    crate::isa::arm::aarch64::cpu::fp_traps::collect_sve_underflow(esize, result, status)
}

fn fp16_three_same_status_with_fpcr_without_trap_collection(
    u: u32,
    a_bit: u32,
    opcode: u32,
    n: u16,
    m: u16,
    r: u16,
    fpcr: u32,
) -> u32 {
    let binary = match (u, a_bit, opcode) {
        (0, 0, 0b010) | (1, 0, 0b010) => Some(FpKind::Add),
        (0, 1, 0b010) => Some(FpKind::Sub),
        (1, 1, 0b010) => Some(FpKind::Abd),
        (0, 0, 0b011) => Some(FpKind::Mulx),
        (1, 0, 0b011) => Some(FpKind::Mul),
        (1, 0, 0b111) => Some(FpKind::Div),
        _ => None,
    };
    if let Some(kind) = binary {
        if let Some((_, status)) = controlled_half_binary(kind, n, m, fpcr) {
            return status;
        }
    }
    if fpcr & FPCR_AH != 0 && matches!((u, a_bit, opcode), (0, 0, 0b111) | (0, 1, 0b111)) {
        return 0;
    }
    if fpcr & FPCR_AH != 0
        && matches!(
            (u, a_bit, opcode),
            (0, 0, 0b110) | (0, 1, 0b110) | (1, 0, 0b110) | (1, 1, 0b110)
        )
        && (fp16_is_nan(n) || fp16_is_nan(m))
    {
        return FPSR_IOC;
    }
    if fpcr & FPCR_FZ16 == 0 {
        return fp16_three_same_status(u, a_bit, opcode, n, m, r);
    }
    let n = fp16_flush_input_with_fpcr(n, fpcr);
    let m = fp16_flush_input_with_fpcr(m, fpcr);
    fp16_three_same_status(u, a_bit, opcode, n, m, r)
}
pub(crate) fn fp16_three_same_status_with_fpcr(
    u: u32,
    a_bit: u32,
    opcode: u32,
    n: u16,
    m: u16,
    r: u16,
    fpcr: u32,
) -> u32 {
    let status =
        fp16_three_same_status_with_fpcr_without_trap_collection(u, a_bit, opcode, n, m, r, fpcr);
    crate::isa::arm::aarch64::cpu::fp_traps::collect_underflow(2, u64::from(r), status, fpcr)
}

fn fp_status_from_exact_f64_without_trap_collection(esize: usize, exact: f64, result: u64) -> u32 {
    if !exact.is_finite() {
        return 0;
    }
    match esize {
        2 => {
            let r = result as u16;
            if exact.abs() >= 65520.0 {
                return FPSR_OFC | FPSR_IXC;
            }
            if fp16_is_inf(r) {
                return FPSR_OFC | FPSR_IXC;
            }
            if exact != fp16_to_f64(r) {
                let underflow = fp16_is_tiny(r) || (fp16_is_zero(r) && exact != 0.0);
                FPSR_IXC | if underflow { FPSR_UFC } else { 0 }
            } else {
                0
            }
        }
        4 => {
            let r = result as u32;
            if exact.abs() > f32::MAX as f64 {
                return FPSR_OFC | FPSR_IXC;
            }
            if fp32_is_inf(r) {
                return FPSR_OFC | FPSR_IXC;
            }
            if exact != f32::from_bits(r) as f64 {
                let underflow = fp32_is_tiny(r) || (fp32_is_zero(r) && exact != 0.0);
                FPSR_IXC | if underflow { FPSR_UFC } else { 0 }
            } else {
                0
            }
        }
        _ => 0,
    }
}
pub(crate) fn fp_status_from_exact_f64(esize: usize, exact: f64, result: u64) -> u32 {
    let status = fp_status_from_exact_f64_without_trap_collection(esize, exact, result);
    crate::isa::arm::aarch64::cpu::fp_traps::collect_sve_underflow(esize, result, status)
}

fn fp_status_fscale_without_trap_collection(esize: usize, x: u64, n: i64, result: u64) -> u32 {
    if fp_is_snan_bits(esize, x) {
        return FPSR_IOC;
    }
    if fp_is_nan_bits(esize, x) || fp_is_inf_bits(esize, x) || fp_is_zero_bits(esize, x) {
        return 0;
    }
    if esize == 8 {
        if let Some((mant, exp)) = fp64_mant_exp(x) {
            let top_bit = 63 - mant.leading_zeros() as i64;
            if (exp as i64).saturating_add(n).saturating_add(top_bit) >= 1024 {
                return FPSR_OFC | FPSR_IXC;
            }
        }
        if fp64_is_inf(result) {
            FPSR_OFC | FPSR_IXC
        } else {
            // Scaling is an exponent change. Compare exact normalized integer
            // significands, including subnormal outputs, before adding IXC.
            let exact = match (fp64_mant_exp(x), fp64_mant_exp(result)) {
                (Some((source, source_exp)), Some((rounded, rounded_exp))) => {
                    let a = source.trailing_zeros();
                    let b = rounded.trailing_zeros();
                    source >> a == rounded >> b
                        && i64::from(source_exp)
                            .saturating_add(n)
                            .saturating_add(i64::from(a))
                            == i64::from(rounded_exp) + i64::from(b)
                }
                _ => false,
            };
            if exact {
                0
            } else {
                FPSR_IXC
                    | if fp64_is_tiny(result) || fp64_is_zero(result) {
                        FPSR_UFC
                    } else {
                        0
                    }
            }
        }
    } else {
        let exact = sve_fp_to_f64(esize, x) * exp2_f64(n.clamp(-1023, 1023) as i32);
        if !exact.is_finite() {
            return FPSR_OFC | FPSR_IXC;
        }
        if exact == 0.0 && fp_is_zero_bits(esize, result) {
            return FPSR_UFC | FPSR_IXC;
        }
        fp_status_from_exact_f64(esize, exact, result)
    }
}
pub(crate) fn fp_status_fscale(esize: usize, x: u64, n: i64, result: u64) -> u32 {
    let status = fp_status_fscale_without_trap_collection(esize, x, n, result);
    crate::isa::arm::aarch64::cpu::fp_traps::collect_sve_underflow(esize, result, status)
}

pub(crate) fn fp16_mla_with_fpcr(acc: u16, a: u16, b: u16, fpcr: u32) -> u16 {
    if fpcr & FPCR_AH == 0 {
        return crate::smir::interpret::SmirInterpreter::arm_eval_half_fused(acc, a, b, fpcr).0;
    }

    let (acc, a, b) = if fpcr & FPCR_FZ16 != 0 {
        (
            fp16_flush_input_with_fpcr(acc, fpcr),
            fp16_flush_input_with_fpcr(a, fpcr),
            fp16_flush_input_with_fpcr(b, fpcr),
        )
    } else {
        (acc, a, b)
    };
    if fpcr & FPCR_AH != 0 {
        if let Some(n) = fp16_ah_nan3(acc, a, b) {
            return n;
        }
    }
    let ah_invalid_default = |r| {
        if fp_invalid_fma_default_nan(2, acc as u64, a as u64, b as u64) {
            fp_ah_invalid_default_nan(2, r as u64, fpcr) as u16
        } else {
            r
        }
    };
    if (fpcr >> 22) & 0x3 == 0
        || fp16_is_nan(acc)
        || fp16_is_nan(a)
        || fp16_is_nan(b)
        || fp16_is_inf(acc)
        || fp16_is_inf(a)
        || fp16_is_inf(b)
    {
        return ah_invalid_default(fp16_mla(acc, a, b));
    }
    let exact = fp16_to_f64(acc) + fp16_to_f64(a) * fp16_to_f64(b);
    if exact == 0.0
        && fp_fma_cancelled_zero_rounds_negative(acc as u64, a as u64, b as u64, 16, fpcr)
    {
        return 0x8000;
    }
    f64_to_fp16_bits_with_fpcr(exact, fpcr)
}

#[inline]
pub(crate) fn fp16_int_to_fp_output_status_with_fpcr(
    abs_int: u128,
    raw: u16,
    status: u32,
    fpcr: u32,
) -> (u16, u32) {
    let (result, status) = fp16_flush_output_status_with_fpcr(raw, status, fpcr);
    if fpcr & FPCR_FZ16 != 0 && abs_int != 0 && fp16_is_zero(result) {
        (result, (status & !FPSR_IXC) | FPSR_UFC)
    } else {
        (
            result,
            crate::isa::arm::aarch64::cpu::fp_traps::collect_underflow(
                2,
                u64::from(result),
                status,
                fpcr,
            ),
        )
    }
}

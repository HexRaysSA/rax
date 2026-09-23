//! SIMD, packed, and floating-point vector interpretation

use crate::smir::interpret::*;
use std::collections::HashMap;

use crate::smir::ir::context::{ArchRegState, ExitReason, SmirContext, VecValue};
use crate::smir::ir::flags::{FlagSet, FlagUpdate, LazyFlagOp, LazyFlags};
use crate::smir::ir::memory::{MemoryError, SmirMemory};
use crate::smir::ir::ops::{
    HexFpOp, HexFpRecipKind, OpKind, RvVectorState, SmirOp, X86AdxKind, X86BlsKind,
    X86CacheControlKind, X86CountKind, X86OpHint, X86ThreeDNowKind, X86X87ArithmeticDestination,
    X86X87ArithmeticSource, X86X87CompareSource, X86X87Constant, X86X87ControlKind, X86X87DataKind,
    X86X87EnvWidth, X86X87FloatWidth, X86X87IntWidth, X86XSaveKind,
};
use crate::smir::ir::types::*;
use crate::smir::ir::{CallTarget, SmirBlock, SmirFunction, Terminator, TrapKind};

mod x86_fma;
mod x86_sat_convert;

impl SmirInterpreter {
    pub(crate) fn x86_fp16_to_fp32_bits(bits: u16) -> u32 {
        let sign = u32::from(bits & 0x8000) << 16;
        let exponent = (bits >> 10) & 0x1F;
        let fraction = u32::from(bits & 0x03FF);
        match exponent {
            0 if fraction == 0 => sign,
            0 => {
                let shift = fraction.leading_zeros() - 21;
                let normalized = fraction << shift;
                let unbiased = -14 - shift as i32;
                sign | (((unbiased + 127) as u32) << 23) | ((normalized & 0x03FF) << 13)
            }
            0x1F if fraction == 0 => sign | 0x7F80_0000,
            0x1F => sign | 0x7FC0_0000 | (fraction << 13),
            _ => sign | ((((i32::from(exponent)) - 15 + 127) as u32) << 23) | (fraction << 13),
        }
    }

    pub(crate) fn x86_fp32_to_bf16_bits(bits: u32) -> u16 {
        let sign = (bits >> 16) as u16 & 0x8000;
        let exponent = bits & 0x7F80_0000;
        let fraction = bits & 0x007F_FFFF;
        if exponent == 0 {
            // BF16 conversion always applies DAZ and preserves the zero sign.
            sign
        } else if exponent == 0x7F80_0000 {
            let mut result = (bits >> 16) as u16;
            if fraction != 0 {
                result |= 1 << 6;
            }
            result
        } else {
            let lsb = (bits >> 16) & 1;
            (bits.wrapping_add(0x7FFF + lsb) >> 16) as u16
        }
    }

    pub(crate) fn x86_fp16_to_f32(bits: u16) -> f32 {
        let sign = (u32::from(bits & 0x8000)) << 16;
        let exp = (bits >> 10) & 0x1f;
        let frac = bits & 0x03ff;
        let value = if exp == 0 {
            if frac == 0 {
                sign
            } else {
                let shift = frac.leading_zeros() - 6;
                let normalized = (u32::from(frac) << (shift + 1)) & 0x03ff;
                sign | ((112 - shift) << 23) | (normalized << 13)
            }
        } else if exp == 0x1f {
            sign | 0x7f80_0000 | (u32::from(frac) << 13)
        } else {
            sign | ((u32::from(exp) + 112) << 23) | (u32::from(frac) << 13)
        };
        f32::from_bits(value)
    }

    pub(crate) fn x86_f32_to_fp16(value: f32, rounding: u8) -> u16 {
        let bits = value.to_bits();
        let sign = (bits >> 16) & 0x8000;
        let negative = sign != 0;
        let abs = bits & 0x7fff_ffff;
        let exp = (abs >> 23) as i32;
        let mant = abs & 0x007f_ffff;
        if exp == 0xff {
            if mant == 0 {
                return (sign | 0x7c00) as u16;
            }
            return (sign | 0x7c00 | ((mant >> 13) | 0x0200).max(1)) as u16;
        }
        if abs < 0x3300_0000 {
            if abs != 0
                && (matches!(rounding & 3, 1 if negative) || matches!(rounding & 3, 2 if !negative))
            {
                return (sign | 1) as u16;
            }
            return sign as u16;
        }
        if abs < 0x3880_0000 {
            let mant24 = mant | 0x0080_0000;
            let shift = (126 - exp) as u32;
            let mut half_mant = mant24 >> shift;
            let remainder = mant24 & ((1u32 << shift) - 1);
            if Self::x86_fp16_round_increment(negative, half_mant, remainder, shift, rounding) {
                half_mant += 1;
            }
            return (sign | half_mant) as u16;
        }
        let mut half = (abs - 0x3800_0000) >> 13;
        let remainder = abs & 0x1fff;
        if Self::x86_fp16_round_increment(negative, half, remainder, 13, rounding) {
            half += 1;
        }
        if half >= 0x7c00 {
            let infinity = match rounding & 3 {
                0 => true,
                1 => negative,
                2 => !negative,
                _ => false,
            };
            if infinity {
                (sign | 0x7c00) as u16
            } else {
                (sign | 0x7bff) as u16
            }
        } else {
            (sign | half) as u16
        }
    }

    pub(crate) fn x86_fp16_approx(bits: u16, rsqrt: bool) -> u16 {
        let magnitude = bits & 0x7FFF;
        let fraction = bits & 0x03FF;
        if magnitude & 0x7C00 == 0x7C00 && fraction != 0 {
            // Both instructions quiet NaNs without changing the binary16
            // sign or payload. No SIMD floating-point exception is raised.
            return bits | 0x0200;
        }
        if rsqrt && bits & 0x8000 != 0 && magnitude != 0 {
            // This includes every negative finite nonzero value and -INF.
            return 0xFE00;
        }
        let input = Self::x86_fp16_to_f32(bits);
        let result = if rsqrt {
            1.0f32 / input.sqrt()
        } else {
            1.0f32 / input
        };
        Self::x86_f32_to_fp16(result, 0)
    }

    pub(crate) fn x86_fp16_round_increment(
        negative: bool,
        base: u32,
        remainder: u32,
        shift: u32,
        rounding: u8,
    ) -> bool {
        if remainder == 0 {
            return false;
        }
        match rounding & 3 {
            0 => {
                let half = 1u32 << (shift - 1);
                remainder > half || (remainder == half && (base & 1) != 0)
            }
            1 => negative,
            2 => !negative,
            _ => false,
        }
    }

    pub(crate) fn x86_bf16_to_fp32_daz(bits: u16) -> u32 {
        if bits & 0x7F80 == 0 {
            u32::from(bits & 0x8000) << 16
        } else {
            u32::from(bits) << 16
        }
    }

    pub(crate) fn x86_fp32_ftz(bits: u32) -> u32 {
        if bits & 0x7F80_0000 == 0 {
            bits & 0x8000_0000
        } else {
            bits
        }
    }

    pub(crate) fn x86_bf16_is_nan(bits: u16) -> bool {
        bits & 0x7F80 == 0x7F80 && bits & 0x007F != 0
    }

    pub(crate) fn x86_bf16_quiet_nan(bits: u16) -> u32 {
        u32::from(bits | (1 << 6)) << 16
    }

    /// Sign-extend the low `bits` of `v` to a full i128.
    #[inline]
    pub(crate) fn sext128(v: u128, bits: u32) -> i128 {
        if bits >= 128 {
            v as i128
        } else {
            let shift = 128 - bits;
            ((v << shift) as i128) >> shift
        }
    }

    #[inline]
    pub(crate) fn scalar_shift_count_mask(source_arch: SourceArch, width: OpWidth) -> u64 {
        if source_arch == SourceArch::X86_64 && width != OpWidth::W64 {
            0x1F
        } else {
            0x3F
        }
    }

    pub(crate) fn read_vec(ctx: &SmirContext, reg: VReg) -> VecValue {
        match reg {
            VReg::Virtual(id) => ctx.vregs.get_vec(id),
            VReg::Arch(ArchReg::X86(X86Reg::Mm(n))) => match &ctx.arch_regs {
                ArchRegState::X86_64(x86) => {
                    let mut value = [0; 16];
                    value[0] = x86.mm[n as usize & 0x7];
                    value
                }
                _ => [0; 16],
            },
            VReg::Arch(ArchReg::X86(X86Reg::Xmm(n)))
            | VReg::Arch(ArchReg::X86(X86Reg::Ymm(n)))
            | VReg::Arch(ArchReg::X86(X86Reg::Zmm(n))) => match &ctx.arch_regs {
                ArchRegState::X86_64(x86) => x86.xmm[n as usize],
                _ => [0; 16],
            },
            VReg::Arch(ArchReg::Arm(ArmReg::V(n))) => match &ctx.arch_regs {
                ArchRegState::Aarch64(arm) => {
                    let mut value = [0; 16];
                    value[0] = arm.v[n as usize][0];
                    value[1] = arm.v[n as usize][1];
                    value
                }
                _ => [0; 16],
            },
            VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n))) => match &ctx.arch_regs {
                ArchRegState::Hexagon(hex) => hex.get_v(n),
                _ => [0; 16],
            },
            VReg::Arch(ArchReg::Hexagon(HexagonReg::Q(n))) => match &ctx.arch_regs {
                ArchRegState::Hexagon(hex) => hex.get_q(n),
                _ => [0; 16],
            },
            _ => [0; 16],
        }
    }

    pub(crate) fn write_vec(ctx: &mut SmirContext, reg: VReg, value: VecValue) {
        match reg {
            VReg::Virtual(id) => ctx.vregs.set_vec(id, value),
            VReg::Arch(ArchReg::X86(X86Reg::Mm(n))) => {
                if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                    x86.mm[n as usize & 0x7] = value[0];
                }
            }
            VReg::Arch(ArchReg::X86(X86Reg::Xmm(n)))
            | VReg::Arch(ArchReg::X86(X86Reg::Ymm(n)))
            | VReg::Arch(ArchReg::X86(X86Reg::Zmm(n))) => {
                if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
                    x86.xmm[n as usize] = value;
                }
            }
            VReg::Arch(ArchReg::Arm(ArmReg::V(n))) => {
                if let ArchRegState::Aarch64(arm) = &mut ctx.arch_regs {
                    arm.v[n as usize][0] = value[0];
                    arm.v[n as usize][1] = value[1];
                }
            }
            VReg::Arch(ArchReg::Hexagon(HexagonReg::V(n))) => {
                if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
                    hex.set_v(n, value);
                }
            }
            VReg::Arch(ArchReg::Hexagon(HexagonReg::Q(n))) => {
                if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
                    hex.set_q(n, value);
                }
            }
            _ => {}
        }
    }

    /// Sign extend a value
    pub(crate) fn sign_extend(&self, val: u64, width: OpWidth) -> u64 {
        let sign_bit = width.sign_bit();
        if (val & sign_bit) != 0 {
            val | !width.mask()
        } else {
            val
        }
    }

    /// Read FP register as f64
    pub(crate) fn read_fp(&self, ctx: &SmirContext, vreg: VReg, precision: FpPrecision) -> f64 {
        let bits = ctx.read_vreg(vreg);
        match precision {
            FpPrecision::F16 => {
                // Simplified: treat as f32
                f32::from_bits(bits as u32) as f64
            }
            FpPrecision::F32 => f32::from_bits(bits as u32) as f64,
            FpPrecision::F64 => f64::from_bits(bits),
            FpPrecision::F80 => f64::from_bits(bits), // Simplified
        }
    }

    /// Write FP register from f64
    pub(crate) fn write_fp(
        &self,
        ctx: &mut SmirContext,
        vreg: VReg,
        value: f64,
        precision: FpPrecision,
    ) {
        let bits = match precision {
            FpPrecision::F16 | FpPrecision::F32 => (value as f32).to_bits() as u64,
            FpPrecision::F64 | FpPrecision::F80 => value.to_bits(),
        };
        ctx.write_vreg(vreg, bits);
    }

    pub(crate) fn x86_simd_fp_masks(format: X86SimdFpFormat) -> (u64, u64, u64, u64) {
        let sign = 1u64 << (format.total_bits - 1);
        let fraction = (1u64 << format.fraction_bits) - 1;
        let exponent_field = (1u64 << format.exponent_bits) - 1;
        let exponent = exponent_field << format.fraction_bits;
        let quiet = 1u64 << (format.fraction_bits - 1);
        (sign, exponent, fraction, quiet)
    }

    pub(crate) fn x86_simd_fp_is_nan(bits: u64, format: X86SimdFpFormat) -> bool {
        let (_, exponent, fraction, _) = Self::x86_simd_fp_masks(format);
        bits & exponent == exponent && bits & fraction != 0
    }

    pub(crate) fn x86_simd_fp_is_snan(bits: u64, format: X86SimdFpFormat) -> bool {
        let (_, _, _, quiet) = Self::x86_simd_fp_masks(format);
        Self::x86_simd_fp_is_nan(bits, format) && bits & quiet == 0
    }

    pub(crate) fn x86_simd_fp_is_infinite(bits: u64, format: X86SimdFpFormat) -> bool {
        let (_, exponent, fraction, _) = Self::x86_simd_fp_masks(format);
        bits & exponent == exponent && bits & fraction == 0
    }

    pub(crate) fn x86_simd_fp_is_denormal(bits: u64, format: X86SimdFpFormat) -> bool {
        let (_, exponent, fraction, _) = Self::x86_simd_fp_masks(format);
        bits & exponent == 0 && bits & fraction != 0
    }

    pub(crate) fn x86_simd_fp_is_zero(bits: u64, format: X86SimdFpFormat) -> bool {
        let (sign, _, _, _) = Self::x86_simd_fp_masks(format);
        bits & !sign == 0
    }

    pub(crate) fn x86_simd_fp_quiet_nan(bits: u64, format: X86SimdFpFormat) -> u64 {
        let (_, _, _, quiet) = Self::x86_simd_fp_masks(format);
        bits | quiet
    }

    pub(crate) fn x86_simd_fp_indefinite(format: X86SimdFpFormat) -> u64 {
        let (sign, exponent, _, quiet) = Self::x86_simd_fp_masks(format);
        sign | exponent | quiet
    }

    pub(crate) fn x86_simd_fp_propagate_nan(
        first: u64,
        second: u64,
        format: X86SimdFpFormat,
    ) -> u64 {
        // Intel SDM Table 4-8: SSE/AVX forwards the first source when both
        // sources are NaNs; a sole NaN source is forwarded. SNaNs are quieted.
        if Self::x86_simd_fp_is_nan(first, format) {
            Self::x86_simd_fp_quiet_nan(first, format)
        } else {
            Self::x86_simd_fp_quiet_nan(second, format)
        }
    }

    pub(crate) fn x86_simd_fp_apply_daz(
        bits: u64,
        format: X86SimdFpFormat,
        mxcsr: u32,
    ) -> X86SimdFpResult {
        if !Self::x86_simd_fp_is_denormal(bits, format) {
            return X86SimdFpResult { bits, status: 0 };
        }
        if mxcsr & (1 << 6) != 0 {
            let (sign, _, _, _) = Self::x86_simd_fp_masks(format);
            X86SimdFpResult {
                bits: bits & sign,
                status: 0,
            }
        } else {
            X86SimdFpResult {
                bits,
                status: 1 << 1,
            }
        }
    }

    pub(crate) fn x86_simd_get_exponent(
        bits: u64,
        format: X86SimdFpFormat,
        mxcsr: u32,
    ) -> X86SimdFpResult {
        let (sign, exponent, _, _) = Self::x86_simd_fp_masks(format);
        if Self::x86_simd_fp_is_nan(bits, format) {
            return X86SimdFpResult {
                bits: Self::x86_simd_fp_quiet_nan(bits, format),
                status: u32::from(Self::x86_simd_fp_is_snan(bits, format)),
            };
        }
        if Self::x86_simd_fp_is_infinite(bits, format) {
            return X86SimdFpResult {
                bits: exponent,
                status: 0,
            };
        }
        if Self::x86_simd_fp_is_zero(bits, format) {
            return X86SimdFpResult {
                bits: sign | exponent,
                status: 0,
            };
        }

        let denormal = Self::x86_simd_fp_is_denormal(bits, format);
        if denormal && format.total_bits != 16 && mxcsr & (1 << 6) != 0 {
            return X86SimdFpResult {
                bits: sign | exponent,
                status: 0,
            };
        }

        let finite = Self::x86_simd_fp_decode(bits, format);
        let floor_log2 = (127 - finite.significand.leading_zeros() as i32) + finite.exponent;
        let negative = floor_log2 < 0;
        let magnitude = if negative {
            u128::from((-floor_log2) as u32)
        } else {
            u128::from(floor_log2 as u32)
        };
        let mut result = Self::x86_simd_fp_round_exact(
            negative,
            magnitude,
            0,
            false,
            format,
            FpRoundMode::RoundNearest,
            mxcsr,
        );
        debug_assert_eq!(result.status, 0, "GETEXP integer result must be exact");
        if denormal {
            // AVX512-FP16 does not apply MXCSR.DAZ to FP16 operands. FP32 and
            // FP64 reach this point only when DAZ is clear.
            result.status |= 1 << 1;
        }
        result
    }

    pub(crate) fn x86_simd_get_mantissa(
        bits: u64,
        format: X86SimdFpFormat,
        mxcsr: u32,
        imm: u8,
    ) -> X86SimdFpResult {
        let (sign_mask, exponent_mask, fraction_mask, _) = Self::x86_simd_fp_masks(format);
        if Self::x86_simd_fp_is_nan(bits, format) {
            return X86SimdFpResult {
                bits: Self::x86_simd_fp_quiet_nan(bits, format),
                status: u32::from(Self::x86_simd_fp_is_snan(bits, format)),
            };
        }

        let sign_control = (imm >> 2) & 3;
        let normalization_interval = imm & 3;
        let force_positive = sign_control & 1 != 0;
        let reject_negative = sign_control & 2 != 0;
        let negative = bits & sign_mask != 0;
        let fraction = bits & fraction_mask;
        let exponent_field = (bits & exponent_mask) >> format.fraction_bits;
        let denormal = exponent_field == 0 && fraction != 0;
        let daz = format.total_bits != 16 && mxcsr & (1 << 6) != 0;
        let zero = exponent_field == 0 && (fraction == 0 || daz);
        let infinity = exponent_field == (1u64 << format.exponent_bits) - 1;
        let one = (format.bias as u64) << format.fraction_bits;

        if !negative && (zero || infinity) {
            return X86SimdFpResult {
                bits: one,
                status: 0,
            };
        }
        if negative {
            let signed_one = if force_positive { one } else { sign_mask | one };
            if zero {
                return X86SimdFpResult {
                    bits: signed_one,
                    status: 0,
                };
            }
            if infinity {
                return if reject_negative {
                    X86SimdFpResult {
                        bits: Self::x86_simd_fp_indefinite(format),
                        status: 1,
                    }
                } else {
                    X86SimdFpResult {
                        bits: signed_one,
                        status: 0,
                    }
                };
            }
            if reject_negative {
                return X86SimdFpResult {
                    bits: Self::x86_simd_fp_indefinite(format),
                    status: 1,
                };
            }
        }

        let (normalized_fraction, unbiased_exponent) = if denormal {
            let fraction_msb = 63 - fraction.leading_zeros() as i32;
            let shift = format.fraction_bits as i32 - fraction_msb;
            (
                (fraction << shift as u32) & fraction_mask,
                1 - format.bias - format.fraction_bits as i32 + fraction_msb,
            )
        } else {
            (fraction, exponent_field as i32 - format.bias)
        };
        let result_exponent = match normalization_interval {
            0 => format.bias,
            1 => {
                if unbiased_exponent & 1 != 0 {
                    format.bias - 1
                } else {
                    format.bias
                }
            }
            2 => format.bias - 1,
            3 => {
                let leading_fraction = 1u64 << (format.fraction_bits - 1);
                if normalized_fraction & leading_fraction != 0 {
                    format.bias - 1
                } else {
                    format.bias
                }
            }
            _ => unreachable!(),
        };
        X86SimdFpResult {
            bits: if force_positive { 0 } else { bits & sign_mask }
                | ((result_exponent as u64) << format.fraction_bits)
                | normalized_fraction,
            status: if denormal { 1 << 1 } else { 0 },
        }
    }

    pub(crate) fn x86_simd_round_scale(
        bits: u64,
        format: X86SimdFpFormat,
        mxcsr: u32,
        imm: u8,
    ) -> X86SimdFpResult {
        if Self::x86_simd_fp_is_nan(bits, format) {
            return X86SimdFpResult {
                bits: Self::x86_simd_fp_quiet_nan(bits, format),
                status: u32::from(Self::x86_simd_fp_is_snan(bits, format)),
            };
        }
        if Self::x86_simd_fp_is_infinite(bits, format) || Self::x86_simd_fp_is_zero(bits, format) {
            return X86SimdFpResult { bits, status: 0 };
        }

        let (sign_mask, exponent_mask, _, _) = Self::x86_simd_fp_masks(format);
        // AVX-512 FP16 arithmetic ignores DAZ. FP32/FP64 RNDSCALE converts a
        // denormal operand to signed zero when MXCSR.DAZ is set, without a
        // precision result because the architecturally consumed input is zero.
        let bits = if format.total_bits != 16
            && mxcsr & (1 << 6) != 0
            && Self::x86_simd_fp_is_denormal(bits, format)
        {
            bits & sign_mask
        } else {
            bits
        };
        if Self::x86_simd_fp_is_zero(bits, format) {
            return X86SimdFpResult { bits, status: 0 };
        }

        let mode = if imm & 4 != 0 {
            match (mxcsr >> 13) & 3 {
                0 => FpRoundMode::RoundNearest,
                1 => FpRoundMode::RoundDown,
                2 => FpRoundMode::RoundUp,
                _ => FpRoundMode::RoundTowardZero,
            }
        } else {
            match imm & 3 {
                0 => FpRoundMode::RoundNearest,
                1 => FpRoundMode::RoundDown,
                2 => FpRoundMode::RoundUp,
                _ => FpRoundMode::RoundTowardZero,
            }
        };
        let finite = Self::x86_simd_fp_decode(bits, format);
        let grid_exponent = -i32::from(imm >> 4);
        if finite.exponent >= grid_exponent {
            // The least-significant source bit is already no finer than the
            // selected 2^-M grid, so scaling and rounding are exact no-ops.
            return X86SimdFpResult { bits, status: 0 };
        }

        let (magnitude, rounded_exponent, inexact) = Self::x86_simd_fp_round_shift(
            finite.significand,
            finite.exponent,
            false,
            grid_exponent - finite.exponent,
            mode,
            finite.negative,
        );
        debug_assert_eq!(rounded_exponent, grid_exponent);
        // FP16 RNDSCALE does not apply FTZ. The selected grid result is exact
        // in the source format; any loss is solely the grid-rounding step.
        let rounded = Self::x86_simd_fp_round_exact(
            finite.negative,
            magnitude,
            grid_exponent,
            false,
            format,
            mode,
            if format.total_bits == 16 {
                mxcsr & !(1 << 15)
            } else {
                mxcsr
            },
        );
        debug_assert_eq!(rounded.status & !((1 << 4) | (1 << 5)), 0);
        let mut status = rounded.status & (1 << 4);
        if inexact && imm & 8 == 0 {
            status |= 1 << 5;
        }
        // Only the FP16 forms can produce a tiny grid result: M = 15 selects
        // 2^-15, below the FP16 minimum normal 2^-14. Their operation reports
        // underflow independently of SPE when the grid rounding was inexact.
        // A tiny result is non-zero (SDM Vol. 1 4.9.1.5), so a grid result
        // rounded to signed zero reports only precision.
        if format.total_bits == 16
            && inexact
            && rounded.bits & exponent_mask == 0
            && rounded.bits & !sign_mask != 0
        {
            status |= 1 << 4;
        }
        X86SimdFpResult {
            bits: rounded.bits,
            status,
        }
    }

    pub(crate) fn x86_simd_reduce(
        bits: u64,
        format: X86SimdFpFormat,
        mxcsr: u32,
        imm: u8,
    ) -> X86SimdFpResult {
        if Self::x86_simd_fp_is_nan(bits, format) {
            return X86SimdFpResult {
                bits: Self::x86_simd_fp_quiet_nan(bits, format),
                status: u32::from(Self::x86_simd_fp_is_snan(bits, format)),
            };
        }
        if Self::x86_simd_fp_is_infinite(bits, format) {
            return X86SimdFpResult { bits: 0, status: 0 };
        }

        let (sign_mask, _, _, _) = Self::x86_simd_fp_masks(format);
        // AVX-512 FP16 arithmetic ignores DAZ. FP32/FP64 REDUCE consumes a
        // denormal operand as signed zero when DAZ is enabled, but REDUCE does
        // not report the denormal-operand exception.
        let bits = if format.total_bits != 16
            && mxcsr & (1 << 6) != 0
            && Self::x86_simd_fp_is_denormal(bits, format)
        {
            bits & sign_mask
        } else {
            bits
        };
        let mode = if imm & 4 != 0 {
            match (mxcsr >> 13) & 3 {
                0 => FpRoundMode::RoundNearest,
                1 => FpRoundMode::RoundDown,
                2 => FpRoundMode::RoundUp,
                _ => FpRoundMode::RoundTowardZero,
            }
        } else {
            match imm & 3 {
                0 => FpRoundMode::RoundNearest,
                1 => FpRoundMode::RoundDown,
                2 => FpRoundMode::RoundUp,
                _ => FpRoundMode::RoundTowardZero,
            }
        };
        if Self::x86_simd_fp_is_zero(bits, format) {
            return X86SimdFpResult {
                bits: if mode == FpRoundMode::RoundDown {
                    sign_mask
                } else {
                    0
                },
                status: 0,
            };
        }

        let grid = Self::x86_simd_round_scale(bits, format, mxcsr, imm);
        // The subtraction must not reinterpret its single architectural
        // source through DAZ. MXCSR.FTZ still controls a tiny result; REDUCE
        // then filters the helper's underflow status because its architectural
        // exception set contains only invalid and precision.
        let mut remainder =
            Self::x86_simd_fp_add(bits, grid.bits ^ sign_mask, format, mode, mxcsr & !(1 << 6));
        if format.total_bits != 16
            && mxcsr & (1 << 15) != 0
            && Self::x86_simd_fp_is_denormal(remainder.bits, format)
        {
            remainder.bits &= sign_mask;
            remainder.status |= (1 << 4) | (1 << 5);
        }
        // Intel hardware does not expose precision from the internal
        // round-to-grid step. Only the final subtraction (including an FTZ
        // flush above) contributes architectural precision status.
        let mut status = remainder.status & ((1 << 0) | (1 << 5));
        if imm & 8 != 0 {
            status &= !(1 << 5);
        }
        remainder.status = status;
        remainder
    }

    pub(crate) fn x86_simd_range(
        first_bits: u64,
        second_bits: u64,
        format: X86SimdFpFormat,
        mxcsr: u32,
        imm: u8,
    ) -> X86SimdFpResult {
        let (sign, _, _, _) = Self::x86_simd_fp_masks(format);
        if Self::x86_simd_fp_is_snan(first_bits, format) {
            return X86SimdFpResult {
                bits: Self::x86_simd_fp_quiet_nan(first_bits, format),
                status: 1,
            };
        }
        if Self::x86_simd_fp_is_snan(second_bits, format) {
            return X86SimdFpResult {
                bits: Self::x86_simd_fp_quiet_nan(second_bits, format),
                status: 1,
            };
        }

        let first_qnan = Self::x86_simd_fp_is_nan(first_bits, format);
        let second_qnan = Self::x86_simd_fp_is_nan(second_bits, format);
        let first_daz = Self::x86_simd_fp_apply_daz(first_bits, format, mxcsr);
        let second_daz = Self::x86_simd_fp_apply_daz(second_bits, format, mxcsr);
        let first = first_daz.bits;
        let second = second_daz.bits;
        let mut status = 0;
        if !second_qnan {
            status |= first_daz.status;
        }
        if !first_qnan {
            status |= second_daz.status;
        }

        let first_magnitude = first & !sign;
        let second_magnitude = second & !sign;
        let first_negative = first & sign != 0;
        let second_negative = second & sign != 0;
        let compare = imm & 3;
        let selected = if second_qnan {
            first
        } else if first_qnan {
            second
        } else if first_magnitude == 0 && second_magnitude == 0 && first_negative != second_negative
        {
            if compare & 1 == 0 { sign } else { 0 }
        } else if first_magnitude == second_magnitude
            && first_magnitude != 0
            && first_negative != second_negative
            && compare >= 2
        {
            if compare == 2 {
                sign | first_magnitude
            } else {
                first_magnitude
            }
        } else {
            let first_le_second = if first_negative != second_negative {
                first_negative
            } else if first_negative {
                first_magnitude >= second_magnitude
            } else {
                first_magnitude <= second_magnitude
            };
            match compare {
                0 => {
                    if first_le_second {
                        first
                    } else {
                        second
                    }
                }
                1 => {
                    if first_le_second {
                        second
                    } else {
                        first
                    }
                }
                2 => {
                    if first_magnitude <= second_magnitude {
                        first
                    } else {
                        second
                    }
                }
                _ => {
                    if first_magnitude <= second_magnitude {
                        second
                    } else {
                        first
                    }
                }
            }
        };
        let selected_magnitude = selected & !sign;
        let result_sign = match (imm >> 2) & 3 {
            0 => first & sign,
            1 => selected & sign,
            2 => 0,
            _ => sign,
        };
        X86SimdFpResult {
            bits: result_sign | selected_magnitude,
            status,
        }
    }

    pub(crate) fn x86_simd_fixup_imm(
        dest_bits: u64,
        src_bits: u64,
        table_bits: u64,
        format: X86SimdFpFormat,
        mxcsr: u32,
        imm: u8,
    ) -> X86SimdFpResult {
        let (sign_mask, exponent_mask, fraction_mask, quiet_mask) = Self::x86_simd_fp_masks(format);
        // The SDM operation applies DAZ to every exponent-zero encoding and
        // explicitly substitutes +0.0, including for -0 and negative
        // subnormal inputs. VFIXUPIMM never reports the denormal exception.
        let src = if mxcsr & (1 << 6) != 0 && src_bits & exponent_mask == 0 {
            0
        } else {
            src_bits
        };
        let exponent = src & exponent_mask;
        let fraction = src & fraction_mask;
        let is_nan = exponent == exponent_mask && fraction != 0;
        let token = if is_nan {
            if fraction & quiet_mask != 0 { 0 } else { 1 }
        } else if exponent == 0 && fraction == 0 {
            2
        } else {
            let positive_one = match format.total_bits {
                32 => 0x3F80_0000,
                64 => 0x3FF0_0000_0000_0000,
                _ => unreachable!("VFIXUPIMM supports FP32 and FP64"),
            };
            if src == positive_one {
                3
            } else if exponent == exponent_mask && src & sign_mask != 0 {
                4
            } else if exponent == exponent_mask {
                5
            } else if src & sign_mask != 0 {
                6
            } else {
                7
            }
        };
        let response = ((table_bits >> (token * 4)) & 0x0F) as u8;
        let (
            positive_infinity,
            indefinite_nan,
            positive_half,
            positive_ninety,
            positive_pi_2,
            max_finite,
        ) = match format.total_bits {
            32 => (
                0x7F80_0000,
                0xFFC0_0000,
                0x3F00_0000,
                0x42B4_0000,
                0x3FC9_0FDB,
                0x7F7F_FFFF,
            ),
            64 => (
                0x7FF0_0000_0000_0000,
                0xFFF8_0000_0000_0000,
                0x3FE0_0000_0000_0000,
                0x4056_8000_0000_0000,
                0x3FF9_21FB_5444_2D18,
                0x7FEF_FFFF_FFFF_FFFF,
            ),
            _ => unreachable!("VFIXUPIMM supports FP32 and FP64"),
        };
        let positive_one = match format.total_bits {
            32 => 0x3F80_0000,
            64 => 0x3FF0_0000_0000_0000,
            _ => unreachable!(),
        };
        let bits = match response {
            0x0 => dest_bits,
            0x1 => src,
            0x2 => {
                if is_nan {
                    src | quiet_mask
                } else {
                    positive_infinity | quiet_mask
                }
            }
            0x3 => indefinite_nan,
            0x4 => sign_mask | positive_infinity,
            0x5 => positive_infinity,
            0x6 => (src & sign_mask) | positive_infinity,
            0x7 => sign_mask,
            0x8 => 0,
            0x9 => sign_mask | positive_one,
            0xA => positive_one,
            0xB => positive_half,
            0xC => positive_ninety,
            0xD => positive_pi_2,
            0xE => max_finite,
            0xF => sign_mask | max_finite,
            _ => unreachable!(),
        };
        let status = match token {
            1 if imm & (1 << 4) != 0 => 1 << 0,
            2 => u32::from(imm & (1 << 1) != 0) << 0 | u32::from(imm & (1 << 0) != 0) << 2,
            3 => u32::from(imm & (1 << 3) != 0) << 0 | u32::from(imm & (1 << 2) != 0) << 2,
            4 if imm & (1 << 5) != 0 => 1 << 0,
            5 if imm & (1 << 7) != 0 => 1 << 0,
            6 if imm & (1 << 6) != 0 => 1 << 0,
            _ => 0,
        };
        X86SimdFpResult { bits, status }
    }

    pub(crate) fn x86_simd_exp2(bits: u64, format: X86SimdFpFormat) -> X86SimdFpResult {
        let (sign, exponent, _, _) = Self::x86_simd_fp_masks(format);
        let one = (format.bias as u64) << format.fraction_bits;
        if Self::x86_simd_fp_is_nan(bits, format) {
            return X86SimdFpResult {
                bits: Self::x86_simd_fp_quiet_nan(bits, format),
                status: u32::from(Self::x86_simd_fp_is_snan(bits, format)),
            };
        }
        if Self::x86_simd_fp_is_denormal(bits, format) || Self::x86_simd_fp_is_zero(bits, format) {
            // VEXP2 consumes every denormal encoding as +0 independently of
            // DAZ. Both signs of zero and every denormal therefore produce +1.
            return X86SimdFpResult {
                bits: one,
                status: 0,
            };
        }
        if Self::x86_simd_fp_is_infinite(bits, format) {
            return X86SimdFpResult {
                bits: if bits & sign != 0 { 0 } else { exponent },
                status: 0,
            };
        }

        // Apply Intel's finite-domain cutoffs before fixed-point conversion.
        // VEXP2 never emits a denormal result: values below the minimum normal
        // output are flushed to +0 independently of MXCSR.FTZ.
        match format.total_bits {
            32 if bits & sign == 0 && bits > 0x42FF_FFFF => {
                return X86SimdFpResult {
                    bits: exponent,
                    status: 1 << 3,
                };
            }
            32 if bits & sign != 0 && bits > 0xC2FC_0000 => {
                return X86SimdFpResult { bits: 0, status: 0 };
            }
            64 => {
                let biased_exponent = (bits & exponent) >> format.fraction_bits;
                if biased_exponent >= (format.bias + 10) as u64 {
                    return X86SimdFpResult {
                        bits: if bits & sign == 0 { exponent } else { 0 },
                        status: u32::from(bits & sign == 0) << 3,
                    };
                }
            }
            _ => {}
        }

        let input = match format.total_bits {
            32 => f64::from(f32::from_bits(bits as u32)),
            64 => f64::from_bits(bits),
            _ => unreachable!("VEXP2 supports FP32 and FP64"),
        };

        // Intel's reference algorithm decomposes x into a signed scale and a
        // 24-bit fixed-point fraction. Multiplication by 2^24 is exact for the
        // finite domain above; the conversion is explicitly round-to-nearest,
        // ties-to-even and is therefore independent of MXCSR.RC.
        let scaled = input * 16_777_216.0;
        let rounded = scaled.round_ties_even();
        let fixed = rounded as i64;
        let scale = (fixed >> 24) as i32;
        let exact_integer = rounded == scaled && fixed & 0xFF_FFFF == 0;
        let (mut significand, fraction_exponent) = if exact_integer {
            (1u64 << 63, 1023)
        } else {
            Self::x86_exp2_emulate_fraction(((fixed as u64) << 4) & 0x0FFF_FFFF)
        };

        let bits = match format.total_bits {
            32 => {
                let mut final_scale = scale + fraction_exponent + 127 - 1023;
                final_scale = final_scale.max(-25);
                while final_scale <= 0 {
                    final_scale += 1;
                    significand = (significand >> 1) | (significand & 1);
                }

                // Round the normalized fixed-point significand to binary32,
                // preserving a sticky bit while handling a carry-out.
                let increment = 1u64 << 39;
                let mut round_state = (significand >> 39) & 3;
                if significand & (increment - 1) != 0 {
                    round_state |= 2;
                }
                if round_state == 3 {
                    significand = significand.wrapping_add(increment);
                }
                if significand < increment {
                    final_scale += 1;
                    significand = (significand >> 1) | (1u64 << 63);
                }

                let result = significand >> 40;
                if result < (1 << 23) {
                    0
                } else if final_scale > 254 {
                    return X86SimdFpResult {
                        bits: exponent,
                        status: 1 << 3,
                    };
                } else {
                    ((final_scale as u64) << 23) | (result & 0x7F_FFFF)
                }
            }
            64 => {
                // VEXP2PD deliberately returns about 23 significant bits even
                // though the destination is binary64.
                let half_ulp = 1u64 << 39;
                let increment = if significand & (half_ulp - 1) != 0 || (significand >> 39) & 3 == 3
                {
                    half_ulp
                } else {
                    0
                };
                significand = significand.wrapping_add(increment) & !0xFF_FFFF_FFFF;
                let mut final_scale = scale + fraction_exponent;
                if significand == 0 {
                    significand = 1u64 << 63;
                    final_scale += 1;
                }
                final_scale = final_scale.max(-54);
                while final_scale <= 0 {
                    final_scale += 1;
                    significand = (significand >> 1) | (significand & 1);
                }

                let result = significand >> 11;
                if result < (1u64 << 52) {
                    0
                } else if final_scale > 2046 {
                    return X86SimdFpResult {
                        bits: exponent,
                        status: 1 << 3,
                    };
                } else {
                    ((final_scale as u64) << 52) | (result & 0xF_FFFF_FFFF_FFFF)
                }
            }
            _ => unreachable!(),
        };
        X86SimdFpResult { bits, status: 0 }
    }

    pub(crate) fn x86_simd_recip14(
        bits: u64,
        format: X86SimdFpFormat,
        mxcsr: u32,
    ) -> X86SimdFpResult {
        let (sign_mask, exponent_mask, fraction_mask, quiet_mask) = Self::x86_simd_fp_masks(format);
        if Self::x86_simd_fp_is_nan(bits, format) {
            return X86SimdFpResult {
                bits: Self::x86_simd_fp_quiet_nan(bits, format),
                status: 0,
            };
        }
        if Self::x86_simd_fp_is_infinite(bits, format) {
            return X86SimdFpResult {
                bits: bits & sign_mask,
                status: 0,
            };
        }
        if Self::x86_simd_fp_is_zero(bits, format) {
            return X86SimdFpResult {
                bits: (bits & sign_mask) | exponent_mask,
                status: 0,
            };
        }

        let sign = bits & sign_mask;
        let magnitude = bits & !sign_mask;
        let ftz = mxcsr & (1 << 15) != 0;
        let daz = mxcsr & (1 << 6) != 0;
        let max_biased_exponent = (1u64 << format.exponent_bits) - 1;
        let hidden = 1u64 << format.fraction_bits;

        let mut result = if Self::x86_simd_fp_is_denormal(bits, format) {
            let small_denormal_threshold = 1u64 << (format.fraction_bits - 2);
            if daz || magnitude <= small_denormal_threshold {
                sign | exponent_mask
            } else {
                // Intel's reference normalizes large denormals recursively and
                // starts the reciprocal exponent one below the largest normal.
                let mut normalized = magnitude;
                let mut output_exponent = max_biased_exponent - 3;
                while normalized & hidden == 0 {
                    normalized <<= 1;
                    output_exponent += 1;
                }
                let normalized_fraction = normalized & fraction_mask;
                let base = if normalized_fraction == 0 {
                    (format.bias as u64) << format.fraction_bits
                } else {
                    Self::x86_recip14_normalized_base(normalized_fraction, format)
                };
                if base == (format.bias as u64) << format.fraction_bits {
                    output_exponent += 1;
                }
                sign | (output_exponent << format.fraction_bits) | (base & fraction_mask)
            }
        } else {
            let input_exponent = (magnitude & exponent_mask) >> format.fraction_bits;
            let fraction = magnitude & fraction_mask;
            if fraction == 0 {
                if input_exponent == max_biased_exponent - 1 {
                    // The exact reciprocal of the largest power of two is a
                    // denormal whose sole set bit equals the NaN quiet bit.
                    sign | quiet_mask
                } else {
                    let output_exponent = 2 * format.bias as u64 - input_exponent;
                    sign | (output_exponent << format.fraction_bits)
                }
            } else {
                let base = Self::x86_recip14_normalized_base(fraction, format);
                let significand = hidden | (base & fraction_mask);
                if input_exponent == max_biased_exponent - 1 {
                    sign | (significand >> 2)
                } else if input_exponent == max_biased_exponent - 2 {
                    sign | (significand >> 1)
                } else {
                    let output_exponent = 2 * format.bias as u64 - 1 - input_exponent;
                    sign | (output_exponent << format.fraction_bits) | (base & fraction_mask)
                }
            }
        };

        if ftz && result & exponent_mask == 0 && result & fraction_mask != 0 {
            result = sign;
        }
        X86SimdFpResult {
            bits: result,
            status: 0,
        }
    }

    pub(crate) fn x86_recip14_normalized_base(fraction: u64, format: X86SimdFpFormat) -> u64 {
        let segment = (fraction >> (format.fraction_bits - 6)) as usize;
        let retained_fraction = fraction & !((1u64 << (format.fraction_bits - 16)) - 1);
        let center = ((2 * segment + 1) as u64) << (format.fraction_bits - 7);
        let delta = retained_fraction as i128 - center as i128;
        let denominator = 1i128 << (format.fraction_bits - 8);
        let (slope, free_term) = X86_RCP14_COEFFICIENTS[segment];
        let numerator = free_term as i128 * denominator - slope as i128 * delta;
        let significand = numerator >> (format.fraction_bits - 7);
        debug_assert!((1 << 16..=1 << 17).contains(&significand));
        if significand == 1 << 17 {
            (format.bias as u64) << format.fraction_bits
        } else {
            ((format.bias as u64 - 1) << format.fraction_bits)
                | ((significand as u64 - (1 << 16)) << (format.fraction_bits - 16))
        }
    }

    pub(crate) fn x86_simd_rsqrt14(
        bits: u64,
        format: X86SimdFpFormat,
        mxcsr: u32,
    ) -> X86SimdFpResult {
        let (sign_mask, exponent_mask, fraction_mask, quiet_mask) = Self::x86_simd_fp_masks(format);
        if Self::x86_simd_fp_is_nan(bits, format) {
            return X86SimdFpResult {
                bits: Self::x86_simd_fp_quiet_nan(bits, format),
                status: 0,
            };
        }

        let sign = bits & sign_mask;
        let magnitude = bits & !sign_mask;
        if Self::x86_simd_fp_is_denormal(bits, format) && mxcsr & (1 << 6) != 0 {
            return X86SimdFpResult {
                bits: sign | exponent_mask,
                status: 0,
            };
        }
        if sign != 0 && magnitude != 0 {
            return X86SimdFpResult {
                bits: sign_mask | exponent_mask | quiet_mask,
                status: 0,
            };
        }
        if Self::x86_simd_fp_is_infinite(bits, format) {
            return X86SimdFpResult { bits: 0, status: 0 };
        }
        if Self::x86_simd_fp_is_zero(bits, format) {
            return X86SimdFpResult {
                bits: sign | exponent_mask,
                status: 0,
            };
        }

        let hidden = 1u64 << format.fraction_bits;
        let input_exponent = (magnitude & exponent_mask) >> format.fraction_bits;
        let (unbiased_exponent, fraction) = if input_exponent == 0 {
            let mut exponent = 1 - format.bias;
            let mut significand = magnitude & fraction_mask;
            while significand & hidden == 0 {
                significand <<= 1;
                exponent -= 1;
            }
            (exponent, significand & fraction_mask)
        } else {
            (
                input_exponent as i32 - format.bias,
                magnitude & fraction_mask,
            )
        };
        let odd_exponent = unbiased_exponent & 1 != 0;
        let base = if !odd_exponent && fraction == 0 {
            // Every exact even power of two recursively reaches 1.0, for
            // which Intel's reference specifies the exact result 1.0.
            (format.bias as u64) << format.fraction_bits
        } else {
            Self::x86_rsqrt14_normalized_base(fraction, odd_exponent, format)
        };
        let scale = if odd_exponent {
            (unbiased_exponent - 1) / 2
        } else {
            unbiased_exponent / 2
        };
        let scaled = base as i128 - scale as i128 * (1i128 << format.fraction_bits);
        debug_assert!((0..=u64::MAX as i128).contains(&scaled));
        X86SimdFpResult {
            bits: scaled as u64,
            status: 0,
        }
    }

    pub(crate) fn x86_rsqrt14_normalized_base(
        fraction: u64,
        odd_exponent: bool,
        format: X86SimdFpFormat,
    ) -> u64 {
        let segment = (fraction >> (format.fraction_bits - 5)) as usize;
        let retained_fraction = fraction & !((1u64 << (format.fraction_bits - 15)) - 1);
        let center = ((2 * segment + 1) as u64) << (format.fraction_bits - 6);
        let delta = retained_fraction as i128 - center as i128;
        let denominator = 1i128 << format.fraction_bits;
        let coefficient = 2 * segment + usize::from(odd_exponent);
        let (slope, free_term) = X86_RSQRT14_COEFFICIENTS[coefficient];
        // Both reference branches reduce to the same scale: [1,2) multiplies
        // its slope by 2^8, while [2,4) multiplies by 2^7 and has twice the
        // centered significand displacement. Dividing by 2^19 and truncating
        // to 17 significant bits is therefore an integer division by 2^2.
        let numerator = free_term as i128 * denominator - 256 * slope as i128 * delta;
        let significand = numerator >> (format.fraction_bits + 2);
        debug_assert!((1 << 16..=1 << 17).contains(&significand));
        if significand == 1 << 17 {
            (format.bias as u64) << format.fraction_bits
        } else {
            ((format.bias as u64 - 1) << format.fraction_bits)
                | ((significand as u64 - (1 << 16)) << (format.fraction_bits - 16))
        }
    }

    pub(crate) fn x86_simd_recip28(bits: u64, format: X86SimdFpFormat) -> X86SimdFpResult {
        let (sign, exponent, _, _) = Self::x86_simd_fp_masks(format);
        if Self::x86_simd_fp_is_nan(bits, format) {
            return X86SimdFpResult {
                bits: Self::x86_simd_fp_quiet_nan(bits, format),
                status: u32::from(Self::x86_simd_fp_is_snan(bits, format)),
            };
        }
        if Self::x86_simd_fp_is_denormal(bits, format) || Self::x86_simd_fp_is_zero(bits, format) {
            return X86SimdFpResult {
                bits: (bits & sign) | exponent,
                status: 1 << 2,
            };
        }
        if Self::x86_simd_fp_is_infinite(bits, format) {
            return X86SimdFpResult {
                bits: bits & sign,
                status: 0,
            };
        }

        let (_, _, fraction_mask, _) = Self::x86_simd_fp_masks(format);
        let biased_exponent = ((bits & exponent) >> format.fraction_bits) as i32;
        let input_scale = biased_exponent - format.bias;
        let fraction = bits & fraction_mask;
        let (significand, polynomial_exponent) = if fraction == 0 {
            (1u64 << 63, 1023)
        } else {
            let argument = match format.total_bits {
                32 => ((bits as u32).wrapping_shl(7) & 0x3FFF_FFFF) as u64,
                64 => (bits >> 22) & 0x3FFF_FFFF,
                _ => unreachable!("VRCP28 supports FP32 and FP64"),
            };
            Self::x86_approx28_emulate(argument, &X86_RCP28_COEFFICIENTS)
        };
        X86SimdFpResult {
            bits: Self::x86_approx28_finish(
                bits & sign,
                significand,
                polynomial_exponent,
                -input_scale,
                format,
            ),
            status: 0,
        }
    }

    pub(crate) fn x86_simd_rsqrt28(bits: u64, format: X86SimdFpFormat) -> X86SimdFpResult {
        let (sign, exponent, _, _) = Self::x86_simd_fp_masks(format);
        if Self::x86_simd_fp_is_nan(bits, format) {
            return X86SimdFpResult {
                bits: Self::x86_simd_fp_quiet_nan(bits, format),
                status: u32::from(Self::x86_simd_fp_is_snan(bits, format)),
            };
        }
        if Self::x86_simd_fp_is_denormal(bits, format) || Self::x86_simd_fp_is_zero(bits, format) {
            return X86SimdFpResult {
                bits: (bits & sign) | exponent,
                status: 1 << 2,
            };
        }
        if bits & sign != 0 {
            return X86SimdFpResult {
                bits: match format.total_bits {
                    32 => 0xFFC0_0000,
                    64 => 0xFFF8_0000_0000_0000,
                    _ => unreachable!("VRSQRT28 supports FP32 and FP64"),
                },
                status: 1,
            };
        }
        if Self::x86_simd_fp_is_infinite(bits, format) {
            return X86SimdFpResult { bits: 0, status: 0 };
        }

        let (_, _, fraction_mask, _) = Self::x86_simd_fp_masks(format);
        let biased_exponent = ((bits & exponent) >> format.fraction_bits) as i32;
        let input_scale = biased_exponent - format.bias;
        let fraction = bits & fraction_mask;
        let exact_even_power = fraction == 0 && biased_exponent & 1 != 0;
        let (significand, polynomial_exponent) = if exact_even_power {
            (1u64 << 63, 1023)
        } else {
            let argument = match format.total_bits {
                32 => ((bits as u32).wrapping_shl(7) & 0x7FFF_FFFF) as u64,
                64 => (bits >> 22) & 0x7FFF_FFFF,
                _ => unreachable!("VRSQRT28 supports FP32 and FP64"),
            };
            Self::x86_approx28_emulate(argument, &X86_RSQRT28_COEFFICIENTS)
        };
        X86SimdFpResult {
            bits: Self::x86_approx28_finish(
                0,
                significand,
                polynomial_exponent,
                -(input_scale >> 1),
                format,
            ),
            status: 0,
        }
    }

    pub(crate) fn x86_simd_fp_convert_precision(
        bits: u64,
        from: X86SimdFpFormat,
        to: X86SimdFpFormat,
        mode: FpRoundMode,
        mxcsr: u32,
        report_fp16_denormal: bool,
    ) -> X86SimdFpResult {
        let source = if from.total_bits == 16 {
            X86SimdFpResult {
                bits,
                status: if report_fp16_denormal && Self::x86_simd_fp_is_denormal(bits, from) {
                    1 << 1
                } else {
                    0
                },
            }
        } else {
            Self::x86_simd_fp_apply_daz(bits, from, mxcsr)
        };
        let mut status = source.status;
        let (from_sign, _, from_fraction, _) = Self::x86_simd_fp_masks(from);
        let (to_sign, to_exponent, to_fraction, to_quiet) = Self::x86_simd_fp_masks(to);
        let sign = if source.bits & from_sign != 0 {
            to_sign
        } else {
            0
        };

        if Self::x86_simd_fp_is_nan(source.bits, from) {
            if Self::x86_simd_fp_is_snan(source.bits, from) {
                status |= 1;
            }
            let payload = source.bits & from_fraction;
            let payload = if to.fraction_bits >= from.fraction_bits {
                payload << (to.fraction_bits - from.fraction_bits)
            } else {
                payload >> (from.fraction_bits - to.fraction_bits)
            };
            return X86SimdFpResult {
                bits: sign | to_exponent | (payload & to_fraction) | to_quiet,
                status,
            };
        }
        if Self::x86_simd_fp_is_infinite(source.bits, from) {
            return X86SimdFpResult {
                bits: sign | to_exponent,
                status,
            };
        }
        if Self::x86_simd_fp_is_zero(source.bits, from) {
            return X86SimdFpResult { bits: sign, status };
        }

        let finite = Self::x86_simd_fp_decode(source.bits, from);
        let rounded = Self::x86_simd_fp_round_exact(
            finite.negative,
            finite.significand,
            finite.exponent,
            false,
            to,
            mode,
            mxcsr,
        );
        X86SimdFpResult {
            bits: rounded.bits,
            status: status | rounded.status,
        }
    }

    pub(crate) fn x86_simd_fp_decode(bits: u64, format: X86SimdFpFormat) -> X86SimdFinite {
        let (sign, _, fraction_mask, _) = Self::x86_simd_fp_masks(format);
        let exponent_field =
            ((bits >> format.fraction_bits) & ((1u64 << format.exponent_bits) - 1)) as i32;
        let fraction = u128::from(bits & fraction_mask);
        if exponent_field == 0 {
            X86SimdFinite {
                negative: bits & sign != 0,
                significand: fraction,
                exponent: 1 - format.bias - format.fraction_bits as i32,
            }
        } else {
            X86SimdFinite {
                negative: bits & sign != 0,
                significand: fraction | (1u128 << format.fraction_bits),
                exponent: exponent_field - format.bias - format.fraction_bits as i32,
            }
        }
    }

    pub(crate) fn x86_simd_fp_floor_bounded(bits: u64, format: X86SimdFpFormat) -> i32 {
        const LIMIT: u128 = 4096;
        let finite = Self::x86_simd_fp_decode(bits, format);
        let (integer, fractional) = if finite.exponent >= 0 {
            let shift = finite.exponent as u32;
            let integer = if shift >= u128::BITS || finite.significand > (LIMIT >> shift.min(12)) {
                LIMIT
            } else {
                (finite.significand << shift).min(LIMIT)
            };
            (integer, false)
        } else {
            let drop = (-finite.exponent) as u32;
            if drop >= u128::BITS {
                (0, finite.significand != 0)
            } else {
                let integer = finite.significand >> drop;
                let fractional = finite.significand & ((1u128 << drop) - 1) != 0;
                (integer.min(LIMIT), fractional)
            }
        };
        if finite.negative {
            -(integer as i32) - i32::from(fractional && integer < LIMIT)
        } else {
            integer as i32
        }
    }

    pub(crate) fn x86_simd_scale_f(
        first_bits: u64,
        second_bits: u64,
        format: X86SimdFpFormat,
        mode: FpRoundMode,
        mxcsr: u32,
        scalar: bool,
    ) -> X86SimdFpResult {
        let (sign, exponent, _, _) = Self::x86_simd_fp_masks(format);
        let first_nan = Self::x86_simd_fp_is_nan(first_bits, format);
        let second_nan = Self::x86_simd_fp_is_nan(second_bits, format);
        let first_snan = first_nan && Self::x86_simd_fp_is_snan(first_bits, format);
        let second_snan = second_nan && Self::x86_simd_fp_is_snan(second_bits, format);
        if first_snan || (first_nan && second_snan) {
            return X86SimdFpResult {
                bits: Self::x86_simd_fp_quiet_nan(first_bits, format),
                status: 1,
            };
        }
        if second_snan {
            return X86SimdFpResult {
                bits: Self::x86_simd_fp_quiet_nan(second_bits, format),
                status: 1,
            };
        }

        let second_infinite = Self::x86_simd_fp_is_infinite(second_bits, format);
        let second_negative = second_bits & sign != 0;
        // The VSCALEF special-case table treats a quiet NaN in SRC1 as
        // transparent when SRC2 is infinite: +Inf selects +Inf and -Inf
        // selects +0. Other quiet-NaN pairs retain operand priority.
        if first_nan {
            return X86SimdFpResult {
                bits: if second_infinite {
                    if second_negative { 0 } else { exponent }
                } else {
                    Self::x86_simd_fp_quiet_nan(first_bits, format)
                },
                status: 0,
            };
        }
        if second_nan {
            return X86SimdFpResult {
                bits: Self::x86_simd_fp_quiet_nan(second_bits, format),
                status: 0,
            };
        }

        // AVX512-FP16 ignores DAZ. All formats report denormal input only for
        // src1; src2 still participates in scaling but never raises DE.
        let (first, second, status) = if format.total_bits == 16 {
            (
                first_bits,
                second_bits,
                u32::from(Self::x86_simd_fp_is_denormal(first_bits, format)) << 1,
            )
        } else {
            let first = Self::x86_simd_fp_apply_daz(first_bits, format, mxcsr);
            let second = Self::x86_simd_fp_apply_daz(second_bits, format, mxcsr);
            (first.bits, second.bits, first.status)
        };
        let first_sign = first & sign;
        let second_negative = second & sign != 0;
        if Self::x86_simd_fp_is_infinite(first, format) {
            if Self::x86_simd_fp_is_infinite(second, format) && second_negative {
                return X86SimdFpResult {
                    bits: Self::x86_simd_fp_indefinite(format),
                    status: status | 1,
                };
            }
            return X86SimdFpResult {
                bits: first,
                status,
            };
        }
        if Self::x86_simd_fp_is_zero(first, format) {
            if Self::x86_simd_fp_is_infinite(second, format) && !second_negative {
                return X86SimdFpResult {
                    bits: Self::x86_simd_fp_indefinite(format),
                    status: status | 1,
                };
            }
            return X86SimdFpResult {
                bits: first,
                status,
            };
        }
        if Self::x86_simd_fp_is_infinite(second, format) {
            return X86SimdFpResult {
                bits: if second_negative {
                    first_sign
                } else {
                    first_sign | exponent
                },
                status,
            };
        }

        let finite = Self::x86_simd_fp_decode(first, format);
        let scale = Self::x86_simd_fp_floor_bounded(second, format);
        // Intel specifies gradual underflow for packed VSCALEFPH, while the
        // scalar VSCALEFSH form explicitly honors MXCSR.FTZ.
        let round_mxcsr = if format.total_bits == 16 && !scalar {
            mxcsr & !(1 << 15)
        } else {
            mxcsr
        };
        let rounded = Self::x86_simd_fp_round_exact(
            finite.negative,
            finite.significand,
            finite.exponent.saturating_add(scale),
            false,
            format,
            mode,
            round_mxcsr,
        );
        X86SimdFpResult {
            bits: rounded.bits,
            status: status | rounded.status,
        }
    }

    pub(crate) fn x86_simd_fp_to_int(
        bits: u64,
        format: X86SimdFpFormat,
        int_bits: u32,
        signed: bool,
        mode: FpRoundMode,
    ) -> X86SimdFpResult {
        let mask = if int_bits == 64 {
            u64::MAX
        } else {
            (1u64 << int_bits) - 1
        };
        let indefinite = if signed { 1u64 << (int_bits - 1) } else { mask };
        if Self::x86_simd_fp_is_nan(bits, format) || Self::x86_simd_fp_is_infinite(bits, format) {
            return X86SimdFpResult {
                bits: indefinite,
                status: 1,
            };
        }
        if Self::x86_simd_fp_is_zero(bits, format) {
            return X86SimdFpResult { bits: 0, status: 0 };
        }

        let finite = Self::x86_simd_fp_decode(bits, format);
        let (magnitude, inexact) = if finite.exponent >= 0 {
            let shift = finite.exponent as u32;
            if shift >= u128::BITS || finite.significand > (u128::MAX >> shift) {
                return X86SimdFpResult {
                    bits: indefinite,
                    status: 1,
                };
            }
            (finite.significand << shift, false)
        } else {
            let (rounded, rounded_exponent, inexact) = Self::x86_simd_fp_round_shift(
                finite.significand,
                finite.exponent,
                false,
                -finite.exponent,
                mode,
                finite.negative,
            );
            debug_assert_eq!(rounded_exponent, 0);
            (rounded, inexact)
        };

        let valid = if signed {
            let negative_limit = 1u128 << (int_bits - 1);
            if finite.negative {
                magnitude <= negative_limit
            } else {
                magnitude < negative_limit
            }
        } else {
            (!finite.negative || magnitude == 0) && magnitude <= u128::from(mask)
        };
        if !valid {
            return X86SimdFpResult {
                bits: indefinite,
                status: 1,
            };
        }

        let value = if finite.negative {
            0u128.wrapping_sub(magnitude) as u64 & mask
        } else {
            magnitude as u64 & mask
        };
        X86SimdFpResult {
            bits: value,
            status: if inexact { 1 << 5 } else { 0 },
        }
    }

    pub(crate) fn x86_simd_fp_round_up(mode: FpRoundMode, negative: bool, inexact: bool) -> bool {
        inexact
            && matches!(
                (mode, negative),
                (FpRoundMode::RoundUp, false) | (FpRoundMode::RoundDown, true)
            )
    }

    pub(crate) fn x86_simd_fp_round_shift(
        mut magnitude: u128,
        mut exponent: i32,
        sticky: bool,
        drop: i32,
        mode: FpRoundMode,
        negative: bool,
    ) -> (u128, i32, bool) {
        if drop <= 0 {
            let inexact = sticky;
            if Self::x86_simd_fp_round_up(mode, negative, inexact) {
                magnitude += 1;
            }
            return (magnitude, exponent, inexact);
        }
        let drop = drop as u32;
        let dropped = if drop >= 128 {
            magnitude
        } else {
            magnitude & ((1u128 << drop) - 1)
        };
        let half = if (1..=128).contains(&drop) {
            1u128 << (drop - 1)
        } else {
            0
        };
        magnitude = if drop >= 128 { 0 } else { magnitude >> drop };
        exponent += drop as i32;
        let inexact = dropped != 0 || sticky;
        let increment = match mode {
            FpRoundMode::RoundNearest => {
                let round_bit = half != 0 && dropped & half != 0;
                let rest = half != 0 && ((dropped & (half - 1)) != 0 || sticky);
                round_bit && (rest || magnitude & 1 != 0)
            }
            FpRoundMode::RoundUp | FpRoundMode::RoundDown => {
                Self::x86_simd_fp_round_up(mode, negative, inexact)
            }
            FpRoundMode::RoundTowardZero => false,
            _ => unreachable!("x86 SIMD arithmetic requires a resolved MXCSR rounding mode"),
        };
        if increment {
            magnitude += 1;
        }
        (magnitude, exponent, inexact)
    }

    pub(crate) fn x86_simd_fp_unbounded_tiny(
        magnitude: u128,
        exponent: i32,
        sticky: bool,
        format: X86SimdFpFormat,
        mode: FpRoundMode,
        negative: bool,
    ) -> bool {
        let msb = 127 - magnitude.leading_zeros() as i32;
        let drop = msb - format.fraction_bits as i32;
        let (rounded, rounded_exponent, _) =
            Self::x86_simd_fp_round_shift(magnitude, exponent, sticky, drop, mode, negative);
        let rounded_msb = 127 - rounded.leading_zeros() as i32;
        rounded_msb + rounded_exponent < 1 - format.bias
    }

    pub(crate) fn x86_simd_fp_round_exact(
        negative: bool,
        magnitude: u128,
        exponent: i32,
        sticky: bool,
        format: X86SimdFpFormat,
        mode: FpRoundMode,
        mxcsr: u32,
    ) -> X86SimdFpResult {
        let (sign_mask, exponent_mask, fraction_mask, _) = Self::x86_simd_fp_masks(format);
        let sign = if negative { sign_mask } else { 0 };
        if magnitude == 0 {
            return X86SimdFpResult {
                bits: sign,
                status: 0,
            };
        }

        let tiny =
            Self::x86_simd_fp_unbounded_tiny(magnitude, exponent, sticky, format, mode, negative);
        let msb = 127 - magnitude.leading_zeros() as i32;
        let unbiased = msb + exponent;
        let minimum_normal = 1 - format.bias;
        let minimum_subnormal = minimum_normal - format.fraction_bits as i32;
        let lowest_exponent = if unbiased < minimum_normal {
            minimum_subnormal
        } else {
            unbiased - format.fraction_bits as i32
        };
        let (rounded, rounded_exponent, inexact) = Self::x86_simd_fp_round_shift(
            magnitude,
            exponent,
            sticky,
            lowest_exponent - exponent,
            mode,
            negative,
        );
        let mut status = if inexact { 1 << 5 } else { 0 };
        if rounded == 0 {
            if tiny {
                if mxcsr & (1 << 11) == 0 || inexact {
                    status |= 1 << 4;
                }
                if mxcsr & (1 << 15) != 0 && mxcsr & (1 << 11) != 0 {
                    status |= (1 << 4) | (1 << 5);
                }
            }
            return X86SimdFpResult { bits: sign, status };
        }

        let rounded_msb = 127 - rounded.leading_zeros() as i32;
        let rounded_unbiased = rounded_msb + rounded_exponent;
        let maximum_unbiased = format.bias;
        if rounded_unbiased > maximum_unbiased {
            status |= (1 << 3) | (1 << 5);
            let infinity = sign | exponent_mask;
            let max_finite =
                sign | (exponent_mask - (1u64 << format.fraction_bits)) | fraction_mask;
            let bits = match (mode, negative) {
                (FpRoundMode::RoundNearest, _) => infinity,
                (FpRoundMode::RoundTowardZero, _) => max_finite,
                (FpRoundMode::RoundUp, false) | (FpRoundMode::RoundDown, true) => infinity,
                (FpRoundMode::RoundUp, true) | (FpRoundMode::RoundDown, false) => max_finite,
                _ => unreachable!(),
            };
            return X86SimdFpResult { bits, status };
        }

        if tiny {
            if mxcsr & (1 << 11) == 0 || inexact {
                status |= 1 << 4;
            }
            if mxcsr & (1 << 15) != 0 && mxcsr & (1 << 11) != 0 {
                return X86SimdFpResult {
                    bits: sign,
                    status: status | (1 << 4) | (1 << 5),
                };
            }
        }

        let bits = if rounded_unbiased < minimum_normal {
            let fraction = if rounded_exponent >= minimum_subnormal {
                rounded << (rounded_exponent - minimum_subnormal)
            } else {
                rounded >> (minimum_subnormal - rounded_exponent)
            };
            sign | (fraction as u64 & fraction_mask)
        } else {
            let shift = rounded_msb - format.fraction_bits as i32;
            let significand = if shift >= 0 {
                rounded >> shift
            } else {
                rounded << -shift
            };
            let biased = (rounded_unbiased + format.bias) as u64;
            sign | (biased << format.fraction_bits) | (significand as u64 & fraction_mask)
        };
        X86SimdFpResult { bits, status }
    }

    pub(crate) fn x86_simd_fp_mul(
        first: u64,
        second: u64,
        format: X86SimdFpFormat,
        mode: FpRoundMode,
        mxcsr: u32,
    ) -> X86SimdFpResult {
        if let Some(result) = Self::x86_simd_fp_arithmetic_nan(first, second, format) {
            return result;
        }
        let first = Self::x86_simd_fp_apply_daz(first, format, mxcsr);
        let second = Self::x86_simd_fp_apply_daz(second, format, mxcsr);
        let mut status = first.status | second.status;
        let first_inf = Self::x86_simd_fp_is_infinite(first.bits, format);
        let second_inf = Self::x86_simd_fp_is_infinite(second.bits, format);
        let first_zero = Self::x86_simd_fp_is_zero(first.bits, format);
        let second_zero = Self::x86_simd_fp_is_zero(second.bits, format);
        if (first_inf && second_zero) || (second_inf && first_zero) {
            return X86SimdFpResult {
                bits: Self::x86_simd_fp_indefinite(format),
                status: status | 1,
            };
        }
        let (sign_mask, exponent_mask, _, _) = Self::x86_simd_fp_masks(format);
        let negative = (first.bits ^ second.bits) & sign_mask != 0;
        if first_inf || second_inf {
            return X86SimdFpResult {
                bits: if negative { sign_mask } else { 0 } | exponent_mask,
                status,
            };
        }
        if first_zero || second_zero {
            return X86SimdFpResult {
                bits: if negative { sign_mask } else { 0 },
                status,
            };
        }
        let a = Self::x86_simd_fp_decode(first.bits, format);
        let b = Self::x86_simd_fp_decode(second.bits, format);
        let rounded = Self::x86_simd_fp_round_exact(
            negative,
            a.significand * b.significand,
            a.exponent + b.exponent,
            false,
            format,
            mode,
            mxcsr,
        );
        X86SimdFpResult {
            bits: rounded.bits,
            status: status | rounded.status,
        }
    }

    pub(crate) fn x86_simd_fp_add(
        first: u64,
        second: u64,
        format: X86SimdFpFormat,
        mode: FpRoundMode,
        mxcsr: u32,
    ) -> X86SimdFpResult {
        if let Some(result) = Self::x86_simd_fp_arithmetic_nan(first, second, format) {
            return result;
        }
        let first = Self::x86_simd_fp_apply_daz(first, format, mxcsr);
        let second = Self::x86_simd_fp_apply_daz(second, format, mxcsr);
        let mut status = first.status | second.status;
        let first_inf = Self::x86_simd_fp_is_infinite(first.bits, format);
        let second_inf = Self::x86_simd_fp_is_infinite(second.bits, format);
        let (sign_mask, exponent_mask, _, _) = Self::x86_simd_fp_masks(format);
        if first_inf && second_inf && (first.bits ^ second.bits) & sign_mask != 0 {
            return X86SimdFpResult {
                bits: Self::x86_simd_fp_indefinite(format),
                status: status | 1,
            };
        }
        if first_inf || second_inf {
            return X86SimdFpResult {
                bits: if first_inf { first.bits } else { second.bits }
                    & (sign_mask | exponent_mask),
                status,
            };
        }
        let first_zero = Self::x86_simd_fp_is_zero(first.bits, format);
        let second_zero = Self::x86_simd_fp_is_zero(second.bits, format);
        if first_zero && second_zero {
            let negative = if (first.bits ^ second.bits) & sign_mask == 0 {
                first.bits & sign_mask != 0
            } else {
                mode == FpRoundMode::RoundDown
            };
            return X86SimdFpResult {
                bits: if negative { sign_mask } else { 0 },
                status,
            };
        }
        if first_zero || second_zero {
            return X86SimdFpResult {
                bits: if first_zero { second.bits } else { first.bits },
                status,
            };
        }
        let a = Self::x86_simd_fp_decode(first.bits, format);
        let b = Self::x86_simd_fp_decode(second.bits, format);
        let guard = if format.total_bits == 32 { 100 } else { 72 };
        let (negative, magnitude, exponent, sticky) = hr_add_scaled(
            a.negative,
            a.significand,
            a.exponent,
            b.negative,
            b.significand,
            b.exponent,
            guard,
        );
        if magnitude == 0 && !sticky {
            return X86SimdFpResult {
                bits: if mode == FpRoundMode::RoundDown {
                    sign_mask
                } else {
                    0
                },
                status,
            };
        }
        let rounded = Self::x86_simd_fp_round_exact(
            negative, magnitude, exponent, sticky, format, mode, mxcsr,
        );
        X86SimdFpResult {
            bits: rounded.bits,
            status: status | rounded.status,
        }
    }

    pub(crate) fn x86_simd_fp_unmasked(status: u32, mxcsr: u32) -> bool {
        status & 0x3F & !((mxcsr >> 7) & 0x3F) != 0
    }

    pub(crate) fn dynamic_fp_round_mode(&self, ctx: &SmirContext) -> FpRoundMode {
        match &ctx.arch_regs {
            ArchRegState::Aarch64(arm) => match (arm.fpcr >> 22) & 0x3 {
                0b00 => FpRoundMode::RoundNearest,
                0b01 => FpRoundMode::RoundUp,
                0b10 => FpRoundMode::RoundDown,
                _ => FpRoundMode::RoundTowardZero,
            },
            ArchRegState::X86_64(x86) => match (x86.mxcsr >> 13) & 0x3 {
                0b00 => FpRoundMode::RoundNearest,
                0b01 => FpRoundMode::RoundDown,
                0b10 => FpRoundMode::RoundUp,
                _ => FpRoundMode::RoundTowardZero,
            },
            ArchRegState::RiscV(rv) => match (rv.fcsr >> 5) & 0x7 {
                0b000 => FpRoundMode::RoundNearest,
                0b001 => FpRoundMode::RoundTowardZero,
                0b010 => FpRoundMode::RoundDown,
                0b011 => FpRoundMode::RoundUp,
                0b100 => FpRoundMode::RoundNearestTiesAway,
                _ => FpRoundMode::RoundNearest,
            },
            _ => FpRoundMode::RoundNearest,
        }
    }

    pub(crate) fn round_fp_value(&self, ctx: &SmirContext, value: f64, mode: FpRoundMode) -> f64 {
        match match mode {
            FpRoundMode::Dynamic => self.dynamic_fp_round_mode(ctx),
            other => other,
        } {
            FpRoundMode::RoundNearest => value.round_ties_even(),
            FpRoundMode::RoundNearestTiesAway => value.round(),
            FpRoundMode::RoundTowardZero => value.trunc(),
            FpRoundMode::RoundUp => value.ceil(),
            FpRoundMode::RoundDown => value.floor(),
            FpRoundMode::Dynamic => unreachable!(),
        }
    }

    pub(crate) fn x86_f64_to_f32_bits(&self, ctx: &SmirContext, value: f64) -> u32 {
        self.x86_f64_to_f32_bits_mode(ctx, value, FpRoundMode::Dynamic)
    }

    pub(crate) fn x86_f64_to_f32_bits_mode(
        &self,
        ctx: &SmirContext,
        value: f64,
        mode: FpRoundMode,
    ) -> u32 {
        let nearest = value as f32;
        if value.is_nan() || value.is_infinite() || (nearest as f64) == value {
            return nearest.to_bits();
        }
        let (lo, hi) = if nearest.is_infinite() {
            if value.is_sign_negative() {
                (f32::NEG_INFINITY, -f32::MAX)
            } else {
                (f32::MAX, f32::INFINITY)
            }
        } else if (nearest as f64) < value {
            (nearest, Self::next_up_f32(nearest))
        } else {
            (Self::next_down_f32(nearest), nearest)
        };
        let mode = if mode == FpRoundMode::Dynamic {
            self.dynamic_fp_round_mode(ctx)
        } else {
            mode
        };
        let rounded = match mode {
            FpRoundMode::RoundDown => lo,
            FpRoundMode::RoundUp => hi,
            FpRoundMode::RoundTowardZero => {
                if value.is_sign_negative() {
                    hi
                } else {
                    lo
                }
            }
            _ => nearest,
        };
        rounded.to_bits()
    }

    pub(crate) fn next_up_f32(value: f32) -> f32 {
        if value == 0.0 {
            return f32::from_bits(1);
        }
        let bits = value.to_bits();
        f32::from_bits(if value.is_sign_negative() {
            bits - 1
        } else {
            bits + 1
        })
    }

    pub(crate) fn next_down_f32(value: f32) -> f32 {
        if value == 0.0 {
            return f32::from_bits(0x8000_0001);
        }
        let bits = value.to_bits();
        f32::from_bits(if value.is_sign_negative() {
            bits + 1
        } else {
            bits - 1
        })
    }

    pub(crate) fn next_up_f64(value: f64) -> f64 {
        if value == 0.0 {
            return f64::from_bits(1);
        }
        let bits = value.to_bits();
        f64::from_bits(if value.is_sign_negative() {
            bits - 1
        } else {
            bits + 1
        })
    }

    pub(crate) fn next_down_f64(value: f64) -> f64 {
        if value == 0.0 {
            return f64::from_bits(0x8000_0000_0000_0001);
        }
        let bits = value.to_bits();
        f64::from_bits(if value.is_sign_negative() {
            bits + 1
        } else {
            bits - 1
        })
    }

    /// v6mpy product-term table: `(vsel, byte, ci, osel)` — which Vuu vector
    /// (0=lo,1=hi), which byte (0..3) of the word lane, which of the six
    /// coefficients (0=c00..2=c02, 3=c10..5=c12), and which output vector
    /// (0=lo,1=hi). Mirrors sem/hvx_v6mpy.rs H_TERMS / V_TERMS exactly.
    pub(crate) fn v6mpy_terms(horizontal: bool, phase: u8) -> &'static [(u8, u8, u8, u8)] {
        const H_TERMS: [&[(u8, u8, u8, u8)]; 4] = [
            &[
                (1, 3, 3, 1),
                (1, 1, 4, 1),
                (0, 3, 5, 1),
                (1, 2, 0, 1),
                (1, 0, 1, 1),
                (0, 2, 2, 1),
                (1, 2, 3, 0),
                (1, 0, 4, 0),
                (0, 2, 5, 0),
            ],
            &[
                (1, 3, 0, 1),
                (1, 1, 1, 1),
                (0, 3, 2, 1),
                (1, 3, 3, 0),
                (1, 1, 4, 0),
                (0, 3, 5, 0),
                (1, 2, 0, 0),
                (1, 0, 1, 0),
                (0, 2, 2, 0),
            ],
            &[
                (1, 1, 3, 1),
                (0, 3, 4, 1),
                (0, 1, 5, 1),
                (1, 0, 0, 1),
                (0, 2, 1, 1),
                (0, 0, 2, 1),
                (1, 0, 3, 0),
                (0, 2, 4, 0),
                (0, 0, 5, 0),
            ],
            &[
                (1, 1, 0, 1),
                (0, 3, 1, 1),
                (0, 1, 2, 1),
                (1, 1, 3, 0),
                (0, 3, 4, 0),
                (0, 1, 5, 0),
                (1, 0, 0, 0),
                (0, 2, 1, 0),
                (0, 0, 2, 0),
            ],
        ];
        const V_TERMS: [&[(u8, u8, u8, u8)]; 4] = [
            &[
                (0, 3, 3, 1),
                (1, 2, 4, 1),
                (1, 3, 5, 1),
                (0, 1, 0, 1),
                (1, 0, 1, 1),
                (1, 1, 2, 1),
                (0, 1, 3, 0),
                (1, 0, 4, 0),
                (1, 1, 5, 0),
            ],
            &[
                (0, 3, 0, 1),
                (1, 2, 1, 1),
                (1, 3, 2, 1),
                (0, 3, 3, 0),
                (1, 2, 4, 0),
                (1, 3, 5, 0),
                (0, 1, 0, 0),
                (1, 0, 1, 0),
                (1, 1, 2, 0),
            ],
            &[
                (0, 2, 3, 1),
                (0, 3, 4, 1),
                (1, 2, 5, 1),
                (0, 0, 0, 1),
                (0, 1, 1, 1),
                (1, 0, 2, 1),
                (0, 0, 3, 0),
                (0, 1, 4, 0),
                (1, 0, 5, 0),
            ],
            &[
                (0, 2, 0, 1),
                (0, 3, 1, 1),
                (1, 2, 2, 1),
                (0, 2, 3, 0),
                (0, 3, 4, 0),
                (1, 2, 5, 0),
                (0, 0, 0, 0),
                (0, 1, 1, 0),
                (1, 0, 2, 0),
            ],
        ];
        let p = (phase & 3) as usize;
        if horizontal { H_TERMS[p] } else { V_TERMS[p] }
    }

    pub(crate) fn get_lane(value: &VecValue, lane: u8, elem_bits: u32) -> u64 {
        let bit_index = lane as u32 * elem_bits;
        let word_index = (bit_index / 64) as usize;
        let bit_offset = bit_index % 64;

        // VecValue is a fixed 1024-bit (16-word) backing store. A lane whose
        // bits fall outside it has no storage; reading it as 0 keeps an
        // oversized/invalid VLane lane count from indexing out of bounds and
        // panicking (or aborting an aborting build) instead of corrupting memory.
        if word_index >= value.len() {
            return 0;
        }

        if elem_bits == 64 {
            return value[word_index];
        }

        let mask = (1u64 << elem_bits) - 1;
        if bit_offset + elem_bits <= 64 {
            (value[word_index] >> bit_offset) & mask
        } else {
            let low = value[word_index] >> bit_offset;
            let high = value
                .get(word_index + 1)
                .map_or(0, |w| w << (64 - bit_offset));
            (low | high) & mask
        }
    }

    pub(crate) fn set_lane(value: &mut VecValue, lane: u8, elem_bits: u32, bits: u64) {
        let bit_index = lane as u32 * elem_bits;
        let word_index = (bit_index / 64) as usize;
        let bit_offset = bit_index % 64;

        // Out-of-range lanes (see `get_lane`) have no backing storage; drop the
        // write rather than indexing past the 1024-bit VecValue and aborting.
        if word_index >= value.len() {
            return;
        }

        if elem_bits == 64 {
            value[word_index] = bits;
            return;
        }

        let mask = (1u64 << elem_bits) - 1;
        let bits = bits & mask;
        if bit_offset + elem_bits <= 64 {
            let clear = !(mask << bit_offset);
            value[word_index] = (value[word_index] & clear) | (bits << bit_offset);
        } else if word_index + 1 < value.len() {
            let low_bits = 64 - bit_offset;
            let low_mask = (1u64 << low_bits) - 1;
            let high_bits = elem_bits - low_bits;
            let high_mask = (1u64 << high_bits) - 1;

            value[word_index] =
                (value[word_index] & !(low_mask << bit_offset)) | ((bits & low_mask) << bit_offset);
            value[word_index + 1] = (value[word_index + 1] & !high_mask) | (bits >> low_bits);
        }
    }

    pub(crate) fn apply_vector_mask(
        result: &mut VecValue,
        old: &VecValue,
        mask_bits: Option<u64>,
        zeroing: bool,
        width: VecWidth,
        elem: VecElementType,
    ) {
        let Some(mask_bits) = mask_bits else {
            return;
        };
        let bits = elem.bytes() * 8;
        for lane in 0..width.lanes(elem) as u8 {
            if mask_bits & (1u64 << lane) == 0 {
                let inactive = if zeroing {
                    0
                } else {
                    Self::get_lane(old, lane, bits)
                };
                Self::set_lane(result, lane, bits, inactive);
            }
        }
    }

    /// Vector binary operation helper (integer)
    /// Apply a `VLaneOp` to two zero-extended `elem_bits`-wide lane values,
    /// returning the result masked to `elem_bits`. Signed ops sign-extend the
    /// inputs first; saturating ops clamp to the element's signed/unsigned range.
    /// Returns true iff the saturating lane op `op` clamps `(a, b)` out of the
    /// target `elem_bits` range — i.e. the Hexagon `ctx.sat_n`/`ctx.satu_n`
    /// overflow condition. Only `AddSat`/`SubSat` saturate; all other ops never
    /// clamp (return false). Mirrors `apply_lane_op`'s i128 arithmetic exactly so
    /// the clamp detection matches the value path bit-for-bit.
    pub(crate) fn lane_sat_clamped(
        op: VLaneOp,
        a: u64,
        b: u64,
        elem_bits: u32,
        signed: bool,
    ) -> bool {
        let mask: u64 = if elem_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << elem_bits) - 1
        };
        let sx = |v: u64| -> i64 {
            if elem_bits >= 64 {
                v as i64
            } else {
                let shift = 64 - elem_bits;
                ((v << shift) as i64) >> shift
            }
        };
        let smin: i128 = if signed {
            -(1i128 << (elem_bits - 1))
        } else {
            0
        };
        let smax: i128 = if signed {
            (1i128 << (elem_bits - 1)) - 1
        } else {
            mask as i128
        };
        match op {
            VLaneOp::AddSat => {
                if signed {
                    let s = sx(a) as i128 + sx(b) as i128;
                    s < smin || s > smax
                } else {
                    let s = (a & mask) as u128 + (b & mask) as u128;
                    s > mask as u128
                }
            }
            VLaneOp::SubSat => {
                if signed {
                    let s = sx(a) as i128 - sx(b) as i128;
                    s < smin || s > smax
                } else {
                    // Unsigned sub clamps to 0 (matches `ctx.satu_n` on negatives;
                    // an unsigned diff can never exceed `mask`).
                    (a & mask) < (b & mask)
                }
            }
            _ => false,
        }
    }

    pub(crate) fn apply_lane_op(op: VLaneOp, a: u64, b: u64, elem_bits: u32, signed: bool) -> u64 {
        let mask: u64 = if elem_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << elem_bits) - 1
        };
        // Sign-extend a zero-extended `elem_bits` value to i64.
        let sx = |v: u64| -> i64 {
            if elem_bits >= 64 {
                v as i64
            } else {
                let shift = 64 - elem_bits;
                ((v << shift) as i64) >> shift
            }
        };
        let smin: i64 = if elem_bits >= 64 {
            i64::MIN
        } else {
            -(1i64 << (elem_bits - 1))
        };
        let smax: i64 = if elem_bits >= 64 {
            i64::MAX
        } else {
            (1i64 << (elem_bits - 1)) - 1
        };
        let umax: u64 = mask;
        let res: u64 = match op {
            VLaneOp::Add => a.wrapping_add(b),
            VLaneOp::Sub => a.wrapping_sub(b),
            VLaneOp::Mul => a.wrapping_mul(b),
            VLaneOp::And => a & b,
            VLaneOp::Or => a | b,
            VLaneOp::Xor => a ^ b,
            VLaneOp::AndNot => a & !b,
            VLaneOp::OrNot => a | !b,
            VLaneOp::Not => !a,
            VLaneOp::Min => {
                if signed {
                    sx(a).min(sx(b)) as u64
                } else {
                    (a & mask).min(b & mask)
                }
            }
            VLaneOp::Max => {
                if signed {
                    sx(a).max(sx(b)) as u64
                } else {
                    (a & mask).max(b & mask)
                }
            }
            VLaneOp::AddSat => {
                if signed {
                    (sx(a) as i128 + sx(b) as i128).clamp(smin as i128, smax as i128) as u64
                } else {
                    ((a & mask) as u128 + (b & mask) as u128).min(umax as u128) as u64
                }
            }
            VLaneOp::SubSat => {
                if signed {
                    (sx(a) as i128 - sx(b) as i128).clamp(smin as i128, smax as i128) as u64
                } else {
                    (a & mask).saturating_sub(b & mask)
                }
            }
            VLaneOp::Avg => {
                if signed {
                    ((sx(a) as i128 + sx(b) as i128) >> 1) as u64
                } else {
                    (((a & mask) as u128 + (b & mask) as u128) >> 1) as u64
                }
            }
            VLaneOp::AvgRnd => {
                if signed {
                    ((sx(a) as i128 + sx(b) as i128 + 1) >> 1) as u64
                } else {
                    (((a & mask) as u128 + (b & mask) as u128 + 1) >> 1) as u64
                }
            }
            VLaneOp::Sign => {
                if b & mask == 0 {
                    0
                } else if sx(b) < 0 {
                    0u64.wrapping_sub(a)
                } else {
                    a
                }
            }
            VLaneOp::AbsDiff => {
                if signed {
                    (sx(a) as i128 - sx(b) as i128).unsigned_abs() as u64
                } else {
                    let (x, y) = (a & mask, b & mask);
                    if x >= y { x - y } else { y - x }
                }
            }
        };
        res & mask
    }

    pub(crate) fn vec_binary_op<F>(
        &self,
        ctx: &mut SmirContext,
        dst: VReg,
        src1: VReg,
        src2: VReg,
        elem: VecElementType,
        lanes: u8,
        op: F,
    ) where
        F: Fn(u64, u64) -> u64,
    {
        let a = Self::read_vec(ctx, src1);
        let b = Self::read_vec(ctx, src2);

        let elem_bits = elem.bytes() * 8;
        let mut result = [0u64; 16];

        for lane in 0..lanes {
            let a_elem = Self::get_lane(&a, lane, elem_bits);
            let b_elem = Self::get_lane(&b, lane, elem_bits);
            let res_elem = op(a_elem, b_elem);
            Self::set_lane(&mut result, lane, elem_bits, res_elem);
        }

        Self::write_vec(ctx, dst, result);
    }

    pub(crate) fn vec_unary_op<F>(
        &self,
        ctx: &mut SmirContext,
        dst: VReg,
        src: VReg,
        elem: VecElementType,
        lanes: u8,
        op: F,
    ) where
        F: Fn(u64) -> u64,
    {
        let a = Self::read_vec(ctx, src);
        let elem_bits = elem.bytes() * 8;
        let mut result = [0u64; 16];
        for lane in 0..lanes {
            let a_elem = Self::get_lane(&a, lane, elem_bits);
            Self::set_lane(&mut result, lane, elem_bits, op(a_elem));
        }
        Self::write_vec(ctx, dst, result);
    }

    pub(crate) fn vec_unary_op_f32<F>(
        &self,
        ctx: &mut SmirContext,
        dst: VReg,
        src: VReg,
        lanes: u8,
        op: F,
    ) where
        F: Fn(f32) -> f32,
    {
        let a = Self::read_vec(ctx, src);
        let mut result = [0u64; 16];
        for lane in 0..lanes {
            let a_bits = Self::get_lane(&a, lane, 32) as u32;
            let res = op(f32::from_bits(a_bits));
            Self::set_lane(&mut result, lane, 32, res.to_bits() as u64);
        }
        Self::write_vec(ctx, dst, result);
    }

    pub(crate) fn vec_unary_op_f64<F>(
        &self,
        ctx: &mut SmirContext,
        dst: VReg,
        src: VReg,
        lanes: u8,
        op: F,
    ) where
        F: Fn(f64) -> f64,
    {
        let a = Self::read_vec(ctx, src);
        let mut result = [0u64; 16];
        for lane in 0..lanes {
            let a_bits = Self::get_lane(&a, lane, 64);
            let res = op(f64::from_bits(a_bits));
            Self::set_lane(&mut result, lane, 64, res.to_bits());
        }
        Self::write_vec(ctx, dst, result);
    }

    pub(crate) fn vec_binary_op_f32<F>(
        &self,
        ctx: &mut SmirContext,
        dst: VReg,
        src1: VReg,
        src2: VReg,
        lanes: u8,
        op: F,
    ) where
        F: Fn(f32, f32) -> f32,
    {
        let a = Self::read_vec(ctx, src1);
        let b = Self::read_vec(ctx, src2);
        let mut result = [0u64; 16];

        for lane in 0..lanes {
            let a_bits = Self::get_lane(&a, lane, 32) as u32;
            let b_bits = Self::get_lane(&b, lane, 32) as u32;
            let res = op(f32::from_bits(a_bits), f32::from_bits(b_bits));
            Self::set_lane(&mut result, lane, 32, res.to_bits() as u64);
        }

        Self::write_vec(ctx, dst, result);
    }

    pub(crate) fn vec_binary_op_f64<F>(
        &self,
        ctx: &mut SmirContext,
        dst: VReg,
        src1: VReg,
        src2: VReg,
        lanes: u8,
        op: F,
    ) where
        F: Fn(f64, f64) -> f64,
    {
        let a = Self::read_vec(ctx, src1);
        let b = Self::read_vec(ctx, src2);
        let mut result = [0u64; 16];

        for lane in 0..lanes {
            let a_bits = Self::get_lane(&a, lane, 64);
            let b_bits = Self::get_lane(&b, lane, 64);
            let res = op(f64::from_bits(a_bits), f64::from_bits(b_bits));
            Self::set_lane(&mut result, lane, 64, res.to_bits());
        }

        Self::write_vec(ctx, dst, result);
    }
}

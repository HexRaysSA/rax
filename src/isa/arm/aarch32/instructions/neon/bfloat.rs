//! AArch32 BF16 conversions and Advanced SIMD arithmetic.
use super::*;
use crate::isa::arm::aarch32::fp_traps::STATUS;
use crate::isa::arm::aarch64::cpu::{bfdotadd_ebf0, f32_to_bf16_round};
use crate::isa::arm::decoder::{Aarch32Decoder, aarch32::BfloatFields};

impl<M: ArmMemory> Executor<'_, M> {
    pub(crate) fn exec_bfloat(&mut self, insn: &DecodedInsn) -> ExecResult {
        let Some(Ok(fields)) = Aarch32Decoder::bfloat_fields(insn.raw) else {
            return ExecResult::Undefined;
        };
        if fields.mnemonic() != insn.mnemonic {
            return ExecResult::Undefined;
        }

        let mut standard = self.standard_simd_fp_controls();
        let vfp = &mut self.cpu.vfp;
        match fields {
            BfloatFields::ScalarConvert { d, m, top } => {
                let source = vfp.read_s_bits(m);
                let shift = 16 * u32::from(top);
                let value = u32::from(convert(source, &mut vfp.fpscr)) << shift;
                vfp.write_s_bits(d, (vfp.read_s_bits(d) & !(0xffff << shift)) | value);
            }
            BfloatFields::VectorConvert { d, m } => {
                let inputs = [vfp.read_d_bits(m), vfp.read_d_bits(m + 1)];
                let mut result = 0;
                for (pair, word) in inputs.into_iter().enumerate() {
                    for lane in 0..2 {
                        let value = convert((word >> (32 * lane)) as u32, &mut standard);
                        result |= u64::from(value) << (16 * (2 * pair + lane));
                    }
                }
                vfp.write_d_bits(d, result);
            }
            BfloatFields::Dot {
                d,
                n,
                m,
                registers,
                index,
            } => {
                let indexed = index.map(|lane| pair(vfp.read_d_bits(m), lane));
                for register in 0..registers {
                    let acc = vfp.read_d_bits(d + register);
                    let lhs = vfp.read_d_bits(n + register);
                    let mut result = 0;
                    for lane in 0..2 {
                        let rhs =
                            indexed.unwrap_or_else(|| pair(vfp.read_d_bits(m + register), lane));
                        let value = bfdotadd_ebf0(pair(acc, lane), pair(lhs, lane), rhs);
                        result |= u64::from(value) << (32 * lane);
                    }
                    vfp.write_d_bits(d + register, result);
                }
            }
            BfloatFields::Matrix { d, n, m } => {
                let lhs = [vfp.read_d_bits(n), vfp.read_d_bits(n + 1)];
                let rhs = [vfp.read_d_bits(m), vfp.read_d_bits(m + 1)];
                for (row, lhs_row) in (0..2).zip(lhs) {
                    let acc = vfp.read_d_bits(d + row);
                    let mut result = 0;
                    for (column, rhs_column) in (0..2).zip(rhs) {
                        let first =
                            bfdotadd_ebf0(pair(acc, column), pair(lhs_row, 0), pair(rhs_column, 0));
                        let value = bfdotadd_ebf0(first, pair(lhs_row, 1), pair(rhs_column, 1));
                        result |= u64::from(value) << (32 * column);
                    }
                    vfp.write_d_bits(d + row, result);
                }
            }
            BfloatFields::WideningFma {
                d,
                n,
                m,
                index,
                top,
            } => {
                let indexed = index.map(|lane| widen(vfp.read_d_bits(m), lane));
                for register in 0..2 {
                    let acc = vfp.read_d_bits(d + register);
                    let lhs = vfp.read_d_bits(n + register);
                    let mut result = 0;
                    for lane in 0..2 {
                        let half = 2 * lane + u8::from(top);
                        let rhs =
                            indexed.unwrap_or_else(|| widen(vfp.read_d_bits(m + register), half));
                        let value = vfma_f32(
                            f32::from_bits(pair(acc, lane)),
                            widen(lhs, half),
                            rhs,
                            &mut standard,
                        );
                        result |= u64::from(value.to_bits()) << (32 * lane);
                    }
                    vfp.write_d_bits(d + register, result);
                }
            }
        }
        vfp.fpscr = Fpscr::from_bits(vfp.fpscr.bits() | (standard.bits() & STATUS));
        ExecResult::Continue
    }
}

fn pair(word: u64, lane: u8) -> u32 {
    (word >> (32 * lane)) as u32
}

fn widen(word: u64, lane: u8) -> f32 {
    let half = (word >> (16 * lane)) as u16;
    f32::from_bits(u32::from(half) << 16)
}

fn convert(value: u32, fpscr: &mut Fpscr) -> u16 {
    let magnitude = value & 0x7fff_ffff;
    if magnitude > 0x7f80_0000 {
        if value & (1 << 22) == 0 {
            fpscr.set_ioc(true);
        }
        if fpscr.dn() {
            return 0x7fc0;
        }
    }
    let tiny = magnitude != 0 && magnitude < 0x0080_0000;
    if tiny && fpscr.fz() {
        fpscr.set_idc(true);
        return ((value >> 16) as u16) & 0x8000;
    }
    let result = f32_to_bf16_round(value, fpscr.rmode() as u32);
    if magnitude < 0x7f80_0000 {
        let inexact = value & 0xffff != 0;
        // AArch32 tests tininess before rounding and signals even an exact
        // subnormal result when the underflow exception is enabled.
        if tiny && (inexact || fpscr.bits() & (1 << 11) != 0) {
            fpscr.set_ufc(true);
        }
        if result & 0x7fff == 0x7f80 {
            fpscr.set_ofc(true);
        }
        if inexact {
            fpscr.set_ixc(true);
        }
    }
    result
}

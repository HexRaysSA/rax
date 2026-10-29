//! tests::sve tests

use super::*;
use crate::isa::arm::aarch64::cpu::*;

#[test]
fn test_sve2_dupq_rejects_unallocated_quadword_without_panicking() {
    let mut cpu = create_cpu_with_insn(0x0530_2420); // Unallocated .Q form; Arm XML 2025-12.
    cpu.config.features |= ArmFeatures::SVE2 | ArmFeatures::SVE2P1;
    let src_lo = 0x0123_4567_89ab_cdef;
    let src_hi = 0xfedc_ba98_7654_3210;

    cpu.set_simd_reg(1, src_lo, src_hi).unwrap();

    let before = (cpu.pc, cpu.v, cpu.insn_count);
    assert_eq!(cpu.step().unwrap(), CpuExit::Undefined(0x0530_2420));
    assert_eq!((cpu.pc, cpu.v, cpu.insn_count), before);
}

#[test]
fn test_sve2_dupq_doubleword_remains_allocated() {
    // LLVM 23: DUPQ Z0.D, Z1.D[0], the largest allocated element width.
    let mut cpu = create_cpu_with_insn(0x0528_2420);
    cpu.config.features |= ArmFeatures::SVE2 | ArmFeatures::SVE2P1;
    let value = 0x0123_4567_89ab_cdef;
    cpu.set_simd_reg(1, value, !value).unwrap();
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.get_simd_reg(0), Some((value, value)));
}
#[test]
fn sve_pred_whole_register_ldst_address_wraps_no_panic() {
    // #17: SVE LDR/STR of a predicate register accesses addr and addr+1.
    // With base=u64::MAX the second-byte address (addr+1) overflowed and
    // panicked; it must wrap. WrappingMemory makes the byte reads/writes
    // succeed so the addr+1 path is actually exercised (not short-circuited
    // by a first-byte fault).
    let mut cpu = create_wrapping_memory_cpu();
    cpu.set_x(5, u64::MAX); // base
    // LDR Pt, [X5]: 1000010110 imm9=0 000 Rn=5 Pt=0.
    let ldr = (0b1000010110u32 << 22) | (5 << 5);
    assert_eq!(cpu.exec_sve_ldst(ldr).unwrap(), CpuExit::Continue);
    // STR Pt, [X5]: 1110010110 ...
    let str_ = (0b1110010110u32 << 22) | (5 << 5);
    assert_eq!(cpu.exec_sve_ldst(str_).unwrap(), CpuExit::Continue);
}
#[test]
fn sve_integer_compare_zw_updates_predicate_and_flags() {
    // CMPEQ P1.B, P0/Z, Z0.B, Z1.D
    let mut cpu = create_cpu_with_insn(0x2401_2001);
    cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
    cpu.set_simd(
        0,
        u128::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0]),
    );
    cpu.set_simd(
        1,
        u128::from_le_bytes([3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    );
    cpu.set_sve_pred(0, 0xffff);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.sve_pred(1), 0xff08);
    assert!(!cpu.get_n());
    assert!(!cpu.get_z());
    assert!(!cpu.get_c());
    assert!(!cpu.get_v());
}
#[test]
fn sve_fp_predicated_immediate_add_executes() {
    // FADD Z0.S, P0/M, Z0.S, #0.5
    let mut cpu = create_cpu_with_insn(0x6598_8000);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    let one = 1.0f32.to_bits() as u128;
    cpu.set_simd(0, one | (one << 32) | (one << 64) | (one << 96));
    cpu.set_sve_pred(0, 0xffff);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    let one_and_half = 1.5f32.to_bits() as u128;
    assert_eq!(
        cpu.get_simd(0),
        one_and_half | (one_and_half << 32) | (one_and_half << 64) | (one_and_half << 96)
    );
    assert_eq!(cpu.fpsr, 0);
}
#[test]
fn sve_fp_predicated_immediate_maxnm_uses_zero() {
    // FMAXNM Z0.S, P0/M, Z0.S, #0.0
    let mut cpu = create_cpu_with_insn(0x659c_8000);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    let lanes = [-2.0f32, -0.25, 0.75, 2.0];
    let mut value = 0u128;
    for (i, lane) in lanes.into_iter().enumerate() {
        value |= (lane.to_bits() as u128) << (32 * i);
    }
    cpu.set_simd(0, value);
    cpu.set_sve_pred(0, 0xffff);

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    let expected = [0.0f32, 0.0, 0.75, 2.0]
        .into_iter()
        .enumerate()
        .fold(0u128, |acc, (i, lane)| {
            acc | ((lane.to_bits() as u128) << (32 * i))
        });
    assert_eq!(cpu.get_simd(0), expected);
    assert_eq!(cpu.fpsr, 0);
}
#[test]
fn test_sve2_sqshl_s_positive_saturation_no_panic() {
    // SQSHL Z0.S, P0/M, Z0.S, Z1.S. A positive 32-bit source shifted far
    // enough to saturate took the `(1i32<<31)-1` path, which overflows i32
    // and panics in checked builds. It must instead saturate to i32::MAX.
    let mut cpu = create_cpu_with_insn(0x4488_8020);
    cpu.config.features |= ArmFeatures::SVE2;
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_sve_pred(0, 0xffff); // all lanes active
    // Four 32-bit lanes of 0x4000_0000 (positive), each shifted left by 4.
    cpu.set_simd_reg(0, 0x4000_0000_4000_0000, 0x4000_0000_4000_0000)
        .unwrap();
    cpu.set_simd_reg(1, 0x0000_0004_0000_0004, 0x0000_0004_0000_0004)
        .unwrap();

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(
        cpu.get_simd_reg(0),
        Some((0x7fff_ffff_7fff_ffff, 0x7fff_ffff_7fff_ffff))
    );
}
#[test]
fn test_sve2_flogb_double_no_panic() {
    // FLOGB Z0.D, P0/M, Z1.D. For 64-bit elements the saturation bounds were
    // computed as `-(1<<63)` / `(1<<63)-1`, which overflow i64 and panic in
    // checked builds for *any* active lane. A NaN input drives the
    // most-negative result path, so the lane must come out as i64::MIN.
    let mut cpu = create_cpu_with_insn(0x651e_a020);
    cpu.config.features |= ArmFeatures::SVE2;
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_sve_pred(0, 0xffff); // all lanes active
    let nan = 0x7ff8_0000_0000_0000u64; // quiet NaN (double)
    cpu.set_simd_reg(1, nan, nan).unwrap();

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(
        cpu.get_simd_reg(0),
        Some((i64::MIN as u64, i64::MIN as u64))
    );
}
#[test]
fn test_sve2_bgrp_all_ones_mask_no_panic() {
    // BGRP Z0.D, Z1.D, Z2.D. With a 64-bit mask element of all ones every
    // bit of Zn is "selected", so the per-element selected-bit counter `lk`
    // reaches 64. Shifting a u64 by 64 panics under overflow checks, so a
    // guest could crash a checked build; the handler must guard the shift.
    // With every mask bit set the grouped result is just Zn unchanged.
    let mut cpu = create_cpu_with_insn(0x45c2_b820);
    cpu.config.features |= ArmFeatures::SVE2 | ArmFeatures::SVE2_BITPERM;
    let src_lo = 0x0123_4567_89ab_cdef;
    let src_hi = 0xfedc_ba98_7654_3210;
    cpu.set_simd_reg(1, src_lo, src_hi).unwrap();
    cpu.set_simd_reg(2, u64::MAX, u64::MAX).unwrap();

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.get_simd_reg(0), Some((src_lo, src_hi)));
}
#[test]
fn sve_predicated_wide_shift_uses_covered_dword_amounts() {
    let value = 0x0404_0404_0404_0404_0404_0404_0404_0404u128;
    let amounts = (2u128 << 64) | 1u128;
    for (insn, expected) in [
        (0x0418_8020, 0x0101_0101_0101_0101_0202_0202_0202_0202), // ASR
        (0x0419_8020, 0x0101_0101_0101_0101_0202_0202_0202_0202), // LSR
        (0x041b_8020, 0x1010_1010_1010_1010_0808_0808_0808_0808), // LSL
    ] {
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
        cpu.set_sve_pred(0, 0xffff);
        cpu.set_simd(0, value);
        cpu.set_simd(1, amounts);

        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!(cpu.get_simd(0), expected);
    }

    let invalid_d_size = 0x04d8_8020; // ASR Z0.D, P0/M, Z0.D, Z1.D
    let mut cpu = create_cpu_with_insn(invalid_d_size);
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_sve_pred(0, 0xffff);
    assert_eq!(cpu.step().unwrap(), CpuExit::Undefined(invalid_d_size));
}
#[test]
fn sve_fp16_predicated_fmulx_uses_mulx_semantics() {
    let mut cpu = create_cpu_with_insn(0x654a_8020); // FMULX Z0.H, P0/M, Z0.H, Z1.H
    cpu.sysregs.el1.cpacr |= (0b11 << 20) | (0b11 << 16); // FPEN + ZEN
    cpu.set_sve_pred(0, (1 << 0) | (1 << 2)); // lanes H[0] and H[1]
    cpu.set_simd(
        0,
        pack_h_lanes([
            0x4000, // 2.0
            0x0000, // +0.0; FMULX(+0, +inf) => +2.0
            0x3555, // inactive lane must be preserved
            0x3c00, 0, 0, 0, 0,
        ]),
    );
    cpu.set_simd(
        1,
        pack_h_lanes([
            0x4200, // 3.0
            0x7c00, // +inf
            0x7bff, 0, 0, 0, 0, 0,
        ]),
    );

    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);

    let z0 = cpu.get_simd(0);
    assert_eq!(h_lane(z0, 0), 0x4600); // 2.0 * 3.0 = 6.0
    assert_eq!(h_lane(z0, 1), 0x4000); // FMULX special case
    assert_eq!(h_lane(z0, 2), 0x3555); // inactive merge
}
#[test]
fn sve_predicate_sel_s_form_is_undefined() {
    let mut cpu = create_cpu_with_insn(0x2543_4650); // invalid SELS P0, P1, P2, P3
    cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
    cpu.set_sve_pred(0, 0xaaaa);
    cpu.set_sve_pred(1, 0xf0f0);
    cpu.set_sve_pred(2, 0xcccc);
    cpu.set_sve_pred(3, 0x3333);

    assert_eq!(cpu.step().unwrap(), CpuExit::Undefined(0x2543_4650));
    assert_eq!(cpu.sve_pred(0), 0xaaaa);
}
#[test]
fn sve_predicate_permute_rejects_reserved_predicate_bits() {
    let canonical = (0x05 << 24) | (0b10 << 20) | (2 << 16) | (0b010 << 13) | (1 << 5);

    for bit in [9, 4] {
        let insn = canonical | (1 << bit);
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
        cpu.set_sve_pred(0, 0xaaaa);
        cpu.set_sve_pred(1, 0xf0f0);
        cpu.set_sve_pred(2, 0xcccc);

        assert_eq!(cpu.step().unwrap(), CpuExit::Undefined(insn), "bit {bit}");
        assert_eq!(cpu.sve_pred(0), 0xaaaa, "bit {bit}: p0 unchanged");
    }
}
#[test]
fn sve_predicate_rev_rejects_reserved_predicate_bits() {
    let canonical = (0x05 << 24) | (0b110100 << 16) | (0b010000 << 10) | (1 << 5);

    for bit in [9, 4] {
        let insn = canonical | (1 << bit);
        let mut cpu = create_cpu_with_insn(insn);
        cpu.sysregs.el1.cpacr |= 0b11 << 16; // ZEN
        cpu.set_sve_pred(0, 0xaaaa);
        cpu.set_sve_pred(1, 0xf0f0);

        assert_eq!(cpu.step().unwrap(), CpuExit::Undefined(insn), "bit {bit}");
        assert_eq!(cpu.sve_pred(0), 0xaaaa, "bit {bit}: p0 unchanged");
    }
}

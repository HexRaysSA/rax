//! x87 transcendental instruction tests.

use super::*;
use crate::smir::interpret::tests::*;

fn raw(significand: u64, exponent_sign: u16) -> [u8; 10] {
    let mut value = [0u8; 10];
    value[..8].copy_from_slice(&significand.to_le_bytes());
    value[8..].copy_from_slice(&exponent_sign.to_le_bytes());
    value
}

fn raw_i64(value: i64) -> [u8; 10] {
    if value == 0 {
        return raw(0, 0);
    }
    let magnitude = value.unsigned_abs();
    let highest = 63 - magnitude.leading_zeros();
    raw(
        magnitude << (63 - highest),
        0x3FFF + highest as u16 | ((value < 0) as u16) << 15,
    )
}

fn raw_pow2(exponent: i32, negative: bool) -> [u8; 10] {
    raw(
        0x8000_0000_0000_0000,
        (exponent + 16_383) as u16 | ((negative as u16) << 15),
    )
}

fn raw_f64(value: f64) -> [u8; 10] {
    let bits = value.to_bits();
    let sign = (bits >> 63) as u16;
    let exponent = ((bits >> 52) & 0x7FF) as i32;
    let fraction = bits & 0x000F_FFFF_FFFF_FFFF;
    if exponent == 0 {
        assert_eq!(
            fraction, 0,
            "test helper only needs normal f64 values and zero"
        );
        return raw(0, sign << 15);
    }
    assert_ne!(exponent, 0x7FF, "test helper only needs finite f64 values");
    raw(
        ((1u64 << 52) | fraction) << 11,
        (exponent - 1023 + 16_383) as u16 | (sign << 15),
    )
}

fn magnitude(raw: &[u8; 10]) -> (u16, u64) {
    (
        u16::from_le_bytes(raw[8..].try_into().unwrap()) & 0x7FFF,
        u64::from_le_bytes(raw[..8].try_into().unwrap()),
    )
}

fn to_f64(raw: &[u8; 10]) -> f64 {
    let significand = u64::from_le_bytes(raw[..8].try_into().unwrap());
    let exponent_sign = u16::from_le_bytes(raw[8..].try_into().unwrap());
    let exponent = exponent_sign & 0x7FFF;
    if exponent == 0 && significand == 0 {
        return if exponent_sign & 0x8000 != 0 {
            -0.0
        } else {
            0.0
        };
    }
    let unbiased = if exponent == 0 {
        -16_382
    } else {
        exponent as i32 - 16_383
    };
    let value = significand as f64 * 2.0f64.powi(unbiased - 63);
    if exponent_sign & 0x8000 != 0 {
        -value
    } else {
        value
    }
}

fn state_with(values: &[[u8; 10]]) -> crate::smir::X86X87State {
    let mut state = crate::smir::X86X87State::default();
    for (index, value) in values.iter().enumerate() {
        state.set_logical_raw(index as u8, *value);
    }
    state
}

fn execute(bytes: &[u8], state: crate::smir::X86X87State) -> crate::smir::X86X87State {
    let mut ctx = SmirContext::new_x86_64();
    if let ArchRegState::X86_64(x86) = &mut ctx.arch_regs {
        x86.x87 = state;
    }
    let result = execute_lifted_x86(bytes, &mut ctx, &mut FlatMemory::new(1));
    assert!(matches!(result, BlockResult::Exit(ExitReason::Halt)));
    match ctx.arch_regs {
        ArchRegState::X86_64(x86) => x86.x87,
        _ => unreachable!(),
    }
}

fn logical_raw(state: &crate::smir::X86X87State, index: u8) -> [u8; 10] {
    state.regs[state.physical_index(index)]
}

fn assert_relative(actual: f64, expected: f64, tolerance: f64, name: &str) {
    let error = (actual - expected).abs();
    let scale = expected.abs().max(1.0);
    assert!(
        error <= tolerance * scale,
        "{name}: actual={actual:.17e} expected={expected:.17e} error={error:.3e}"
    );
}

fn assert_binary80_ulp(actual: [u8; 10], expected: [u8; 10], limit: u64, name: &str) {
    let actual_sign = actual[9] >> 7;
    let expected_sign = expected[9] >> 7;
    let (actual_exponent, actual_significand) = magnitude(&actual);
    let (expected_exponent, expected_significand) = magnitude(&expected);
    assert_eq!(actual_sign, expected_sign, "{name}: sign");
    assert_eq!(actual_exponent, expected_exponent, "{name}: exponent");
    let distance = actual_significand.abs_diff(expected_significand);
    assert!(
        distance <= limit,
        "{name}: {distance} binary80 ulps (limit {limit}); actual={actual:02X?} expected={expected:02X?}"
    );
}

const POS_ZERO: [u8; 10] = [0; 10];
const NEG_ZERO: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80];
const ONE: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xFF, 0x3F];
const NEG_ONE: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xFF, 0xBF];
const HALF: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xFE, 0x3F];
const NEG_HALF: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xFE, 0xBF];
const POS_INFINITY: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xFF, 0x7F];
const NEG_INFINITY: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xFF, 0xFF];
const PI_NEAREST: [u8; 10] = [0x35, 0xC2, 0x68, 0x21, 0xA2, 0xDA, 0x0F, 0xC9, 0x00, 0x40];
const PI_OVER_TWO_NEAREST: [u8; 10] = [0x35, 0xC2, 0x68, 0x21, 0xA2, 0xDA, 0x0F, 0xC9, 0xFF, 0x3F];
const PI_OVER_FOUR_NEAREST: [u8; 10] = [0x35, 0xC2, 0x68, 0x21, 0xA2, 0xDA, 0x0F, 0xC9, 0xFE, 0x3F];

#[test]
fn lifted_x87_transcendental_exact_points_stack_shapes_and_environment() {
    for (name, opcode, source, expected) in [
        ("F2XM1 +0", 0xF0, POS_ZERO, POS_ZERO),
        ("F2XM1 -0", 0xF0, NEG_ZERO, NEG_ZERO),
        ("F2XM1 +1", 0xF0, ONE, ONE),
        ("F2XM1 -1", 0xF0, NEG_ONE, NEG_HALF),
        ("FSIN +0", 0xFE, POS_ZERO, POS_ZERO),
        ("FSIN -0", 0xFE, NEG_ZERO, NEG_ZERO),
        ("FCOS +0", 0xFF, POS_ZERO, ONE),
        ("FCOS -0", 0xFF, NEG_ZERO, ONE),
    ] {
        let result = execute(&[0xD9, opcode], state_with(&[source]));
        assert_eq!(logical_raw(&result, 0), expected, "{name}");
        assert_eq!(result.top(), 0, "{name}");
        assert_eq!(result.status_word & 0x023F, 0, "{name}");
        assert_eq!(result.instr_ptr, 0x1000, "{name}");
        assert_eq!(result.last_opcode, 0x0100 | opcode as u16, "{name}");
    }

    for (name, opcode, x, y, expected) in [
        ("FYL2X 3*log2(8)", 0xF1, raw_i64(8), raw_i64(3), raw_i64(9)),
        ("FYL2X 3*log2(0.5)", 0xF1, HALF, raw_i64(3), raw_i64(-3)),
        (
            "FYL2XP1 5*log2(4)",
            0xF9,
            raw_i64(3),
            raw_i64(5),
            raw_i64(10),
        ),
        (
            "FYL2XP1 4*log2(0.5)",
            0xF9,
            NEG_HALF,
            raw_i64(4),
            raw_i64(-4),
        ),
    ] {
        let result = execute(&[0xD9, opcode], state_with(&[x, y]));
        assert_eq!(result.top(), 1, "{name}");
        assert_eq!(logical_raw(&result, 0), expected, "{name}");
        assert_eq!(result.status_word & 0x023F, 0, "{name}");
        assert_eq!(result.instr_ptr, 0x1000, "{name}");
        assert_eq!(result.last_opcode, 0x0100 | opcode as u16, "{name}");
    }

    for (name, opcode) in [("FPTAN", 0xF2), ("FSINCOS", 0xFB)] {
        for zero in [POS_ZERO, NEG_ZERO] {
            let result = execute(&[0xD9, opcode], state_with(&[zero]));
            assert_eq!(result.top(), 7, "{name}");
            assert_eq!(logical_raw(&result, 0), ONE, "{name}");
            assert_eq!(logical_raw(&result, 1), zero, "{name}");
            assert_eq!(result.status_word & 0x023F, 0, "{name}");
        }
    }
}

#[test]
fn lifted_x87_transcendentals_retain_binary80_inputs_and_match_independent_f64_oracles() {
    let half_plus_binary80_ulp = raw(0x8000_0000_0000_0001, 0x3FFE);
    let at_half = execute(&[0xD9, 0xF0], state_with(&[HALF]));
    let above_half = execute(&[0xD9, 0xF0], state_with(&[half_plus_binary80_ulp]));
    assert_ne!(
        logical_raw(&at_half, 0),
        logical_raw(&above_half, 0),
        "F2XM1 must not narrow its binary80 source to binary64"
    );

    let one_plus_binary80_ulp = raw(0x8000_0000_0000_0001, 0x3FFF);
    let logarithm = execute(&[0xD9, 0xF1], state_with(&[one_plus_binary80_ulp, ONE]));
    assert_ne!(logical_raw(&logarithm, 0), POS_ZERO);
    assert!(to_f64(&logical_raw(&logarithm, 0)) > 0.0);

    let input = HALF;
    let sine = execute(&[0xD9, 0xFE], state_with(&[input]));
    let cosine = execute(&[0xD9, 0xFF], state_with(&[input]));
    let tangent = execute(&[0xD9, 0xF2], state_with(&[input]));
    let exp = execute(&[0xD9, 0xF0], state_with(&[input]));
    assert_relative(
        to_f64(&logical_raw(&sine, 0)),
        0.5f64.sin(),
        2.0e-15,
        "FSIN(0.5)",
    );
    assert_relative(
        to_f64(&logical_raw(&cosine, 0)),
        0.5f64.cos(),
        2.0e-15,
        "FCOS(0.5)",
    );
    assert_relative(
        to_f64(&logical_raw(&tangent, 1)),
        0.5f64.tan(),
        3.0e-15,
        "FPTAN(0.5)",
    );
    assert_relative(
        to_f64(&logical_raw(&exp, 0)),
        2.0f64.sqrt() - 1.0,
        2.0e-15,
        "F2XM1(0.5)",
    );

    for result in [&sine, &cosine, &tangent, &exp] {
        assert_ne!(
            result.status_word & 0x0020,
            0,
            "non-exact result must set PE"
        );
    }
}

#[test]
fn lifted_x87_transcendentals_satisfy_intel_ulp_bounds_against_binary128_oracles() {
    // These binary80 reference values were obtained by rounding GNU
    // libquadmath binary128 results, retaining 49 significand bits beyond the
    // 64-bit x87 destination before conversion.  They are independent of the
    // SMIR DD routines; the assertions retain the Intel ULP allowance.
    let cases = [
        (
            "F2XM1(0.5)",
            0xF0,
            state_with(&[HALF]),
            raw(0xD413_CCCF_E779_9211, 0x3FFD),
            1,
            0,
        ),
        (
            "F2XM1(binary80 1/3)",
            0xF0,
            state_with(&[raw(0xAAAA_AAAA_AAAA_AAAB, 0x3FFD)]),
            raw(0x8514_5F31_AE51_5C45, 0x3FFD),
            1,
            0,
        ),
        (
            "FYL2X(3,1.25)",
            0xF1,
            state_with(&[raw_i64(3), raw(0xA000_0000_0000_0000, 0x3FFF)]),
            raw(0xFD98_1064_3D66_14C4, 0x3FFF),
            2,
            0,
        ),
        (
            "FYL2XP1(0.25,1.5)",
            0xF9,
            state_with(&[raw_pow2(-2, false), raw(0xC000_0000_0000_0000, 0x3FFF)]),
            raw(0xF73D_A38D_9D4A_83EB, 0x3FFD),
            2,
            0,
        ),
        (
            "FSIN(0.5)",
            0xFE,
            state_with(&[HALF]),
            raw(0xF577_43A2_582F_7F44, 0x3FFD),
            1,
            0,
        ),
        (
            "FCOS(0.5)",
            0xFF,
            state_with(&[HALF]),
            raw(0xE0A9_4032_DBEA_7CEE, 0x3FFE),
            1,
            0,
        ),
        (
            "FPTAN(0.5)",
            0xF2,
            state_with(&[HALF]),
            raw(0x8BDA_7ADF_9A3A_5219, 0x3FFE),
            1,
            1,
        ),
        (
            "FPATAN(1,3)",
            0xF3,
            state_with(&[raw_i64(3), ONE]),
            raw(0xA4BC_7D19_34F7_0924, 0x3FFD),
            1,
            0,
        ),
    ];

    for (name, opcode, state, expected, limit, logical_index) in cases {
        let result = execute(&[0xD9, opcode], state);
        assert_binary80_ulp(logical_raw(&result, logical_index), expected, limit, name);
    }
}

#[test]
fn lifted_x87_transcendental_dense_dyadic_grid_is_accurate_monotonic_and_symmetric() {
    let mut previous = f64::NEG_INFINITY;
    for numerator in -128..=128 {
        let x = numerator as f64 / 128.0;
        let result = execute(&[0xD9, 0xF0], state_with(&[raw_f64(x)]));
        let actual = to_f64(&logical_raw(&result, 0));
        assert_relative(actual, x.exp2() - 1.0, 3.0e-15, "F2XM1 grid");
        assert!(actual >= previous, "F2XM1 monotonicity at {x}");
        previous = actual;
    }

    for numerator in -96..=96 {
        let x = numerator as f64 / 128.0;
        let input = raw_f64(x);
        let sine = to_f64(&logical_raw(
            &execute(&[0xD9, 0xFE], state_with(&[input])),
            0,
        ));
        let cosine = to_f64(&logical_raw(
            &execute(&[0xD9, 0xFF], state_with(&[input])),
            0,
        ));
        let tangent = to_f64(&logical_raw(
            &execute(&[0xD9, 0xF2], state_with(&[input])),
            1,
        ));
        assert_relative(sine, x.sin(), 3.0e-15, "FSIN grid");
        assert_relative(cosine, x.cos(), 3.0e-15, "FCOS grid");
        assert_relative(tangent, x.tan(), 4.0e-15, "FPTAN grid");
        assert_relative(sine * sine + cosine * cosine, 1.0, 5.0e-15, "sin2+cos2");

        let negative_sine = to_f64(&logical_raw(
            &execute(&[0xD9, 0xFE], state_with(&[raw_f64(-x)])),
            0,
        ));
        let negative_cosine = to_f64(&logical_raw(
            &execute(&[0xD9, 0xFF], state_with(&[raw_f64(-x)])),
            0,
        ));
        assert_eq!(
            negative_sine.to_bits(),
            (-sine).to_bits(),
            "FSIN odd at {x}"
        );
        assert_eq!(
            negative_cosine.to_bits(),
            cosine.to_bits(),
            "FCOS even at {x}"
        );
    }

    for numerator in 64..=256 {
        let x = numerator as f64 / 128.0;
        let result = execute(&[0xD9, 0xF1], state_with(&[raw_f64(x), ONE]));
        assert_relative(
            to_f64(&logical_raw(&result, 0)),
            x.log2(),
            4.0e-15,
            "FYL2X grid",
        );
    }

    for numerator in -128..=128 {
        let x = numerator as f64 / 512.0;
        let result = execute(&[0xD9, 0xF9], state_with(&[raw_f64(x), ONE]));
        assert_relative(
            to_f64(&logical_raw(&result, 0)),
            (1.0 + x).log2(),
            4.0e-15,
            "FYL2XP1 grid",
        );
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn native_x87(
    opcode: u8,
    x: &[u8; 10],
    y: Option<&[u8; 10]>,
) -> ([u8; 10], Option<[u8; 10]>, u16) {
    use std::arch::asm;

    let mut primary = [0u8; 10];
    let mut pushed = [0u8; 10];
    let status: u16;
    // FNSTSW writes AX before the output-buffer pointers are consumed by FSTP.
    // Use an early output so neither pointer can share RAX with the status.
    // SAFETY: each source and destination covers one ten-byte binary80 value;
    // the independent local output arrays remain live through each assembly
    // block. The selected sequence balances the x87 stack after FNINIT, uses
    // no integer stack storage, and preserves integer arithmetic flags.
    match opcode {
        0xF0 => unsafe {
            asm!(
                "fninit",
                "fld tbyte ptr [{x}]",
                "f2xm1",
                "fnstsw ax",
                "fstp tbyte ptr [{primary}]",
                x = in(reg) x.as_ptr(),
                primary = in(reg) primary.as_mut_ptr(),
                out("ax") status,
                options(nostack, preserves_flags),
            );
        },
        0xF1 => unsafe {
            asm!(
                "fninit",
                "fld tbyte ptr [{y}]",
                "fld tbyte ptr [{x}]",
                "fyl2x",
                "fnstsw ax",
                "fstp tbyte ptr [{primary}]",
                x = in(reg) x.as_ptr(),
                y = in(reg) y.unwrap().as_ptr(),
                primary = in(reg) primary.as_mut_ptr(),
                out("ax") status,
                options(nostack, preserves_flags),
            );
        },
        0xF2 => unsafe {
            asm!(
                "fninit",
                "fld tbyte ptr [{x}]",
                "fptan",
                "fnstsw ax",
                "fstp tbyte ptr [{pushed}]",
                "fstp tbyte ptr [{primary}]",
                x = in(reg) x.as_ptr(),
                primary = in(reg) primary.as_mut_ptr(),
                pushed = in(reg) pushed.as_mut_ptr(),
                out("ax") status,
                options(nostack, preserves_flags),
            );
        },
        0xF3 => unsafe {
            asm!(
                "fninit",
                "fld tbyte ptr [{y}]",
                "fld tbyte ptr [{x}]",
                "fpatan",
                "fnstsw ax",
                "fstp tbyte ptr [{primary}]",
                x = in(reg) x.as_ptr(),
                y = in(reg) y.unwrap().as_ptr(),
                primary = in(reg) primary.as_mut_ptr(),
                out("ax") status,
                options(nostack, preserves_flags),
            );
        },
        0xF9 => unsafe {
            asm!(
                "fninit",
                "fld tbyte ptr [{y}]",
                "fld tbyte ptr [{x}]",
                "fyl2xp1",
                "fnstsw ax",
                "fstp tbyte ptr [{primary}]",
                x = in(reg) x.as_ptr(),
                y = in(reg) y.unwrap().as_ptr(),
                primary = in(reg) primary.as_mut_ptr(),
                out("ax") status,
                options(nostack, preserves_flags),
            );
        },
        0xFB => unsafe {
            asm!(
                "fninit",
                "fld tbyte ptr [{x}]",
                "fsincos",
                "fnstsw ax",
                "fstp tbyte ptr [{pushed}]",
                "fstp tbyte ptr [{primary}]",
                x = in(reg) x.as_ptr(),
                primary = in(reg) primary.as_mut_ptr(),
                pushed = in(reg) pushed.as_mut_ptr(),
                out("ax") status,
                options(nostack, preserves_flags),
            );
        },
        0xFE => unsafe {
            asm!(
                "fninit",
                "fld tbyte ptr [{x}]",
                "fsin",
                "fnstsw ax",
                "fstp tbyte ptr [{primary}]",
                x = in(reg) x.as_ptr(),
                primary = in(reg) primary.as_mut_ptr(),
                out("ax") status,
                options(nostack, preserves_flags),
            );
        },
        0xFF => unsafe {
            asm!(
                "fninit",
                "fld tbyte ptr [{x}]",
                "fcos",
                "fnstsw ax",
                "fstp tbyte ptr [{primary}]",
                x = in(reg) x.as_ptr(),
                primary = in(reg) primary.as_mut_ptr(),
                out("ax") status,
                options(nostack, preserves_flags),
            );
        },
        _ => unreachable!(),
    }
    (
        primary,
        matches!(opcode, 0xF2 | 0xFB).then_some(pushed),
        status,
    )
}

#[cfg(target_arch = "x86_64")]
#[test]
fn lifted_x87_transcendentals_match_native_x87_within_combined_error_bounds() {
    for (name, opcode, x, y) in [
        ("F2XM1", 0xF0, HALF, None),
        (
            "FYL2X",
            0xF1,
            raw_i64(3),
            Some(raw(0xA000_0000_0000_0000, 0x3FFF)),
        ),
        ("FPTAN", 0xF2, HALF, None),
        ("FPATAN", 0xF3, raw_i64(3), Some(ONE)),
        (
            "FYL2XP1",
            0xF9,
            raw_pow2(-2, false),
            Some(raw(0xC000_0000_0000_0000, 0x3FFF)),
        ),
        ("FSINCOS", 0xFB, HALF, None),
        ("FSIN", 0xFE, HALF, None),
        ("FCOS", 0xFF, HALF, None),
    ] {
        let state = if let Some(y) = y {
            state_with(&[x, y])
        } else {
            state_with(&[x])
        };
        let interpreted = execute(&[0xD9, opcode], state);
        let interpreted_primary = logical_raw(
            &interpreted,
            if matches!(opcode, 0xF2 | 0xFB) { 1 } else { 0 },
        );
        let (native_primary, native_pushed, native_status) =
            unsafe { native_x87(opcode, &x, y.as_ref()) };
        assert_binary80_ulp(interpreted_primary, native_primary, 4, name);
        if let Some(native_pushed) = native_pushed {
            assert_binary80_ulp(logical_raw(&interpreted, 0), native_pushed, 4, name);
        }
        // Compare exception and stack-fault state.  C0/C3 are architecturally
        // undefined for these operations, while C1 describes rounding of each
        // implementation's permitted approximate result and therefore need
        // not agree across implementations within the shared error bound.
        assert_eq!(
            interpreted.status_word & 0x007F,
            native_status & 0x007F,
            "{name}: exceptions"
        );
        if matches!(opcode, 0xF2 | 0xFB | 0xFE | 0xFF) {
            assert_eq!(interpreted.status_word & 0x0400, 0, "{name}: SMIR C2");
            assert_eq!(native_status & 0x0400, 0, "{name}: native C2");
        }
    }
}

#[test]
fn lifted_x87_trigonometric_range_boundary_is_precise_and_noncommitting() {
    let boundary = raw_pow2(63, false);
    let negative_boundary = raw_pow2(63, true);
    let adjacent_below = raw(u64::MAX, 0x403D);

    for opcode in [0xF2, 0xFB, 0xFE, 0xFF] {
        for source in [boundary, negative_boundary] {
            let mut before = state_with(&[source]);
            before.status_word |= 0x0100 | 0x4000;
            let result = execute(&[0xD9, opcode], before.clone());
            assert_eq!(result.top(), before.top(), "D9 {opcode:02X}");
            assert_eq!(logical_raw(&result, 0), source, "D9 {opcode:02X}");
            assert_eq!(result.tag_word, before.tag_word, "D9 {opcode:02X}");
            assert_eq!(result.status_word & 0x4700, 0x4500, "D9 {opcode:02X}");
            assert_eq!(result.status_word & 0x003F, 0, "D9 {opcode:02X}");
        }

        let mut before = state_with(&[adjacent_below]);
        before.status_word |= 0x0400;
        let result = execute(&[0xD9, opcode], before);
        assert_eq!(result.status_word & 0x0400, 0, "D9 {opcode:02X}");
        if matches!(opcode, 0xF2 | 0xFB) {
            assert_eq!(result.top(), 7, "D9 {opcode:02X}");
        }
    }
}

#[test]
fn lifted_x87_fpatan_signed_zero_infinity_quadrants_and_tiny_ratio() {
    for (name, x, y, expected) in [
        ("atan2(+0,+1)", ONE, POS_ZERO, POS_ZERO),
        ("atan2(-0,+1)", ONE, NEG_ZERO, NEG_ZERO),
        ("atan2(+0,-1)", NEG_ONE, POS_ZERO, PI_NEAREST),
        ("atan2(-0,-1)", NEG_ONE, NEG_ZERO, {
            let mut value = PI_NEAREST;
            value[9] |= 0x80;
            value
        }),
        ("atan2(+1,+0)", POS_ZERO, ONE, PI_OVER_TWO_NEAREST),
        ("atan2(-1,-0)", NEG_ZERO, NEG_ONE, {
            let mut value = PI_OVER_TWO_NEAREST;
            value[9] |= 0x80;
            value
        }),
        (
            "atan2(+inf,+inf)",
            POS_INFINITY,
            POS_INFINITY,
            PI_OVER_FOUR_NEAREST,
        ),
    ] {
        let result = execute(&[0xD9, 0xF3], state_with(&[x, y]));
        assert_eq!(result.top(), 1, "{name}");
        assert_eq!(logical_raw(&result, 0), expected, "{name}");
    }

    for (x, y, expected) in [
        (POS_INFINITY, ONE, 0.0),
        (POS_INFINITY, NEG_ONE, -0.0),
        (NEG_INFINITY, ONE, std::f64::consts::PI),
        (NEG_INFINITY, NEG_ONE, -std::f64::consts::PI),
        (NEG_INFINITY, POS_INFINITY, 3.0 * std::f64::consts::PI / 4.0),
        (
            NEG_INFINITY,
            NEG_INFINITY,
            -3.0 * std::f64::consts::PI / 4.0,
        ),
    ] {
        let result = execute(&[0xD9, 0xF3], state_with(&[x, y]));
        let actual = to_f64(&logical_raw(&result, 0));
        if expected == 0.0 {
            assert_eq!(actual.to_bits(), expected.to_bits());
        } else {
            assert_relative(actual, expected, 2.0e-15, "FPATAN infinity quadrant");
        }
    }

    let minimum_normal = raw_pow2(-16_382, false);
    let result = execute(&[0xD9, 0xF3], state_with(&[ONE, minimum_normal]));
    assert_ne!(logical_raw(&result, 0), POS_ZERO);
    assert_eq!(magnitude(&logical_raw(&result, 0)).0, 1);
}

#[test]
fn lifted_x87_transcendental_pc_rc_rounding_is_explicit_and_monotonic() {
    let mut results = [[[0u8; 10]; 4]; 4];
    for (pc_index, pc) in [0u16, 2, 1, 3].into_iter().enumerate() {
        for rc in 0u16..=3 {
            let mut state = state_with(&[HALF]);
            state.control_word = (state.control_word & !0x0F00) | (pc << 8) | (rc << 10);
            let result = execute(&[0xD9, 0xF0], state);
            results[pc_index][rc as usize] = logical_raw(&result, 0);
            let significand = magnitude(&results[pc_index][rc as usize]).1;
            let discarded_mask = match pc {
                0 => (1u64 << 40) - 1,
                2 => (1u64 << 11) - 1,
                1 | 3 => 0,
                _ => unreachable!(),
            };
            assert_eq!(significand & discarded_mask, 0, "PC={pc} RC={rc}");
        }
        let row = &results[pc_index];
        assert_eq!(row[1], row[3], "positive round-down and truncate agree");
        assert!(magnitude(&row[1]) <= magnitude(&row[0]));
        assert!(magnitude(&row[0]) <= magnitude(&row[2]));
    }
    assert_eq!(
        results[2], results[3],
        "reserved PC=01 follows PC64 profile"
    );

    let tiny = raw_pow2(-50, false);
    for (pc, precision) in [(0u16, 24u32), (2, 53), (1, 64), (3, 64)] {
        let predecessor = raw(u64::MAX << (64 - precision), 0x3FFE);
        for rc in 0u16..=3 {
            let mut state = state_with(&[tiny]);
            state.control_word = (state.control_word & !0x0F00) | (pc << 8) | (rc << 10);
            let result = execute(&[0xD9, 0xFF], state);
            let expected = if matches!(rc, 0 | 2) {
                ONE
            } else {
                predecessor
            };
            assert_eq!(logical_raw(&result, 0), expected, "PC={pc} RC={rc}");
            assert_eq!(result.status_word & 0x0020, 0x0020, "PC={pc} RC={rc}");
            assert_eq!(
                result.status_word & 0x0200 != 0,
                matches!(rc, 0 | 2),
                "PC={pc} RC={rc}"
            );
        }
    }
}

#[test]
fn lifted_x87_transcendental_special_values_masks_and_stack_faults() {
    let qnan = raw(0xC000_0000_0000_1234, 0x7FFF);
    let snan = raw(0xA000_0000_0000_1234, 0x7FFF);
    let quieted_snan = raw(0xE000_0000_0000_1234, 0x7FFF);
    let unsupported = raw(0x4000_0000_0000_0000, 0x3FFF);

    let result = execute(&[0xD9, 0xFE], state_with(&[qnan]));
    assert_eq!(logical_raw(&result, 0), qnan);
    assert_eq!(result.status_word & 0x0001, 0);

    let result = execute(&[0xD9, 0xFE], state_with(&[snan]));
    assert_eq!(logical_raw(&result, 0), quieted_snan);
    assert_eq!(result.status_word & 0x0001, 1);

    for source in [unsupported, POS_INFINITY, NEG_INFINITY] {
        let result = execute(&[0xD9, 0xFE], state_with(&[source]));
        assert_eq!(
            logical_raw(&result, 0),
            crate::smir::X86X87State::INDEFINITE
        );
        assert_eq!(result.status_word & 0x0001, 1);

        let mut state = state_with(&[source]);
        state.control_word &= !0x0001;
        let result = execute(&[0xD9, 0xFE], state);
        assert_eq!(logical_raw(&result, 0), source);
        assert_eq!(result.status_word & 0x8081, 0x8081);
    }

    let minimum_subnormal = raw(1, 0);
    let result = execute(&[0xD9, 0xFE], state_with(&[minimum_subnormal]));
    assert_eq!(logical_raw(&result, 0), minimum_subnormal);
    assert_eq!(result.status_word & 0x0032, 0x0032); // DE | UE | PE

    let mut state = state_with(&[minimum_subnormal]);
    state.control_word &= !0x0002;
    let result = execute(&[0xD9, 0xFE], state);
    assert_eq!(logical_raw(&result, 0), minimum_subnormal);
    assert_eq!(result.status_word & 0x8082, 0x8082);
    assert_eq!(result.status_word & 0x0030, 0);

    let empty = execute(&[0xD9, 0xFE], crate::smir::X86X87State::default());
    assert_eq!(logical_raw(&empty, 0), crate::smir::X86X87State::INDEFINITE);
    assert_eq!(empty.status_word & 0x0241, 0x0041);

    let mut unmasked_empty = crate::smir::X86X87State::default();
    unmasked_empty.control_word &= !1;
    let result = execute(&[0xD9, 0xFE], unmasked_empty.clone());
    assert_eq!(result.top(), unmasked_empty.top());
    assert_eq!(result.tag_word, unmasked_empty.tag_word);
    assert_eq!(result.status_word & 0x80C1, 0x80C1);

    let mut missing_st1 = state_with(&[ONE]);
    missing_st1.status_word |= 0x0200;
    let result = execute(&[0xD9, 0xF1], missing_st1);
    assert_eq!(result.top(), 1);
    assert_eq!(
        logical_raw(&result, 0),
        crate::smir::X86X87State::INDEFINITE
    );
    assert_eq!(result.status_word & 0x0241, 0x0041);

    let mut full_destination = state_with(&[POS_ZERO]);
    full_destination.set_logical_raw(7, ONE);
    let result = execute(&[0xD9, 0xF2], full_destination.clone());
    assert_eq!(result.top(), 7);
    assert_eq!(
        logical_raw(&result, 0),
        crate::smir::X86X87State::INDEFINITE
    );
    assert_eq!(
        logical_raw(&result, 1),
        crate::smir::X86X87State::INDEFINITE
    );
    assert_eq!(result.status_word & 0x0241, 0x0241);

    full_destination.control_word &= !1;
    let result = execute(&[0xD9, 0xF2], full_destination.clone());
    assert_eq!(result.top(), full_destination.top());
    assert_eq!(result.tag_word, full_destination.tag_word);
    assert_eq!(logical_raw(&result, 0), POS_ZERO);
    assert_eq!(result.status_word & 0x82C1, 0x82C1);
}

#[test]
fn lifted_x87_fyl2x_domain_exception_priority_and_pop_commit() {
    let mut negative = state_with(&[NEG_ONE, raw_i64(3)]);
    let result = execute(&[0xD9, 0xF1], negative.clone());
    assert_eq!(result.top(), 1);
    assert_eq!(
        logical_raw(&result, 0),
        crate::smir::X86X87State::INDEFINITE
    );
    assert_eq!(result.status_word & 0x0005, 0x0001);

    negative.control_word &= !1;
    let result = execute(&[0xD9, 0xF1], negative.clone());
    assert_eq!(result.top(), 0);
    assert_eq!(logical_raw(&result, 0), NEG_ONE);
    assert_eq!(logical_raw(&result, 1), raw_i64(3));
    assert_eq!(result.status_word & 0x8081, 0x8081);

    for (y, expected) in [(raw_i64(3), NEG_INFINITY), (raw_i64(-3), POS_INFINITY)] {
        let result = execute(&[0xD9, 0xF1], state_with(&[POS_ZERO, y]));
        assert_eq!(result.top(), 1);
        assert_eq!(logical_raw(&result, 0), expected);
        assert_eq!(result.status_word & 0x0004, 0x0004);
        assert_eq!(result.status_word & 0x0001, 0);
    }

    let result = execute(&[0xD9, 0xF1], state_with(&[POS_ZERO, POS_ZERO]));
    assert_eq!(result.status_word & 0x0005, 0x0001);
    assert_eq!(
        logical_raw(&result, 0),
        crate::smir::X86X87State::INDEFINITE
    );

    let mut unmasked_precision = state_with(&[raw_i64(3), ONE]);
    unmasked_precision.control_word &= !0x0020;
    let result = execute(&[0xD9, 0xF1], unmasked_precision);
    assert_eq!(result.top(), 1);
    assert_eq!(result.status_word & 0x80A0, 0x80A0);
}

#[test]
fn lifted_x87_logarithms_form_the_final_result_before_range_exceptions() {
    let one_plus_binary80_ulp = raw(0x8000_0000_0000_0001, 0x3FFF);
    let minimum_subnormal = raw(1, 0);

    // log2(1 + 2^-63) multiplied by the minimum binary80 subnormal is
    // genuinely below the destination range.  DE, UE, and PE all report on
    // the final result and the masked result rounds to +0.
    let result = execute(
        &[0xD9, 0xF1],
        state_with(&[one_plus_binary80_ulp, minimum_subnormal]),
    );
    assert_eq!(result.top(), 1);
    assert_eq!(logical_raw(&result, 0), POS_ZERO);
    assert_eq!(result.status_word & 0x003A, 0x0032); // DE | UE | PE, not OE

    // The same positive, nonzero result is far below half of the minimum
    // binary80 subnormal.  Directed rounding must nevertheless retain one
    // destination quantum instead of collapsing the computed increment.
    let mut upward = state_with(&[one_plus_binary80_ulp, minimum_subnormal]);
    upward.control_word = (upward.control_word & !0x0C00) | 0x0800;
    let result = execute(&[0xD9, 0xF1], upward);
    assert_eq!(result.top(), 1);
    assert_eq!(logical_raw(&result, 0), minimum_subnormal);
    assert_eq!(result.status_word & 0x023A, 0x0232); // C1 | DE | UE | PE

    // Conversely, FYL2XP1 must not first round this logarithm to a subnormal:
    // multiplying by 2^16383 produces a normal result near 2^-62.47.
    let result = execute(
        &[0xD9, 0xF9],
        state_with(&[minimum_subnormal, raw_pow2(16_383, false)]),
    );
    let output = logical_raw(&result, 0);
    let unbiased = magnitude(&output).0 as i32 - 16_383;
    assert!((-64..=-62).contains(&unbiased), "output={output:02X?}");
    assert_eq!(result.status_word & 0x003A, 0x0022); // DE | PE, not UE/OE

    // A large exact logarithm and maximum finite multiplier overflow only at
    // the final product.  Masked overflow selects +infinity under RC-nearest.
    let maximum_finite = raw(u64::MAX, 0x7FFE);
    let result = execute(
        &[0xD9, 0xF1],
        state_with(&[raw_pow2(16_383, false), maximum_finite]),
    );
    assert_eq!(result.top(), 1);
    assert_eq!(logical_raw(&result, 0), POS_INFINITY);
    assert_eq!(result.status_word & 0x0028, 0x0028); // OE | PE

    let mut unmasked = state_with(&[raw_pow2(16_383, false), maximum_finite]);
    unmasked.control_word &= !0x0008;
    let result = execute(&[0xD9, 0xF1], unmasked);
    assert_eq!(result.top(), 1);
    assert_eq!(result.status_word & 0x80A8, 0x80A8);
    assert_ne!(logical_raw(&result, 0), POS_INFINITY);

    // An unmasked #Z is a pre-computation exception: no destination or TOP
    // update commits.
    let mut unmasked_zero_divide = state_with(&[POS_ZERO, raw_i64(3)]);
    unmasked_zero_divide.control_word &= !0x0004;
    let result = execute(&[0xD9, 0xF1], unmasked_zero_divide);
    assert_eq!(result.top(), 0);
    assert_eq!(logical_raw(&result, 0), POS_ZERO);
    assert_eq!(logical_raw(&result, 1), raw_i64(3));
    assert_eq!(result.status_word & 0x8084, 0x8084);
}

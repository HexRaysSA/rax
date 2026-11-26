//! Selected synchronous support-code boundary for restricted scalar VFP modes.
use rax::isa::arm::aarch32::vfp::Fpscr;
use rax::isa::arm::decoder::{Aarch32Decoder, ThumbDecoder};
use rax::isa::arm::execution::{ArmMemory, FlatMemory};
use rax::isa::arm::{Armv7Cpu, ExceptionType, ExecResult, Executor};
use serde::Deserialize;

#[derive(Deserialize)]
struct Cases {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    rounding: String,
    nan: serde_json::Value,
    flush: String,
    kind: String,
    arm: u32,
    thumb: u32,
}

fn cases() -> Vec<Case> {
    serde_json::from_str::<Cases>(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a32-restricted-fp/cases.json"
    )))
    .unwrap()
    .cases
}

fn controls(index: u32) -> u32 {
    (index & 3) << 22
        | ((index >> 2) & 1) << 25
        | ((index >> 3) & 1) << 24
        | ((index >> 4) & 1) << 19
        | ((index >> 5) & 1) << 26
}

fn configured(thumb: bool, support: u32, control: u32) -> Armv7Cpu {
    let mut cpu = Armv7Cpu::new();
    cpu.cpsr.t = thumb;
    cpu.regs = std::array::from_fn(|index| 0x1122_3300 + index as u32);
    cpu.regs[0] = 0x800;
    cpu.regs[1] = control;
    cpu.regs[15] = 0x100;
    cpu.vfp.dregs.fill(0x3ff0_0000_3f80_0000);
    cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !(15 << 28)) | ((support & 1) << 28);
    cpu.vfp.mvfr1 = (cpu.vfp.mvfr1 & !0xff) | (((support >> 1) & 1) << 4) | ((support >> 2) & 1);
    cpu.vfp.fpscr = Fpscr::from_bits(0xa800_009f | control);
    cpu
}

fn execute(cpu: &mut Armv7Cpu, case: &Case, memory: &mut FlatMemory) -> ExecResult {
    let insn = if cpu.cpsr.t {
        ThumbDecoder::decode_32bit(case.thumb)
    } else {
        Aarch32Decoder::decode(case.arm)
    }
    .unwrap();
    Executor::new(cpu, memory).execute(&insn)
}

// The table records instruction control dependencies from the retained Arm
// pseudocode. This applies the selected synchronous subarchitecture to that
// independent table; no production admission helper supplies expectations.
fn supported(case: &Case, support: u32, control: u32) -> bool {
    let round = support & 1 != 0
        || match case.rounding.as_str() {
            "none" | "nearest" | "convert_zero" => true,
            "fpscr" => control & (3 << 22) == 0,
            "away" | "plus" | "minus" | "zero" => false,
            other => panic!("unknown fixture rounding {other}"),
        };
    let needs_nan = case.nan == true || case.nan == "unless_ahp" && control & (1 << 26) == 0;
    let nan = !needs_nan || support & 2 != 0 || control & (1 << 25) != 0;
    let flush = support & 4 != 0
        || match case.flush.as_str() {
            "none" => true,
            "base" => control & (1 << 24) != 0,
            "half" => control & (1 << 19) != 0,
            other => panic!("unknown fixture flush dependency {other}"),
        };
    round && nan && flush
}

fn arm1176_cpu() -> Armv7Cpu {
    let mut cpu = Armv7Cpu::new();
    cpu.cp15.cpacr = rax::isa::arm::aarch32::cp15::Cpacr::from_bits(0x00f0_0000);
    cpu.vfp.fpsid = 0x4101_20b5;
    cpu.vfp.mvfr0 = 0x1111_1111;
    cpu.vfp.mvfr1 = 0;
    cpu.vfp.mvfr2 = 0;
    cpu.vfp.fpexc = 1 << 30;
    cpu
}

#[test]
fn arm1176_mvfr1_uses_legacy_meaning_for_scalar_modes() {
    // DDI0301H Tables 20-6/20-10 and independent ARM1176 QEMU execution.
    for (name, control, status, single, double) in [
        (
            "reset",
            0,
            0,
            [0x3f80_0000, 0x4000_0000, 0x4040_0000],
            [
                0x3ff0_0000_0000_0000,
                0x4000_0000_0000_0000,
                0x4008_0000_0000_0000,
            ],
        ),
        (
            "round-nearest-tie",
            0,
            0x10,
            [0x3f80_0000, 0x3380_0000, 0x3f80_0000],
            [
                0x3ff0_0000_0000_0000,
                0x3ca0_0000_0000_0000,
                0x3ff0_0000_0000_0000,
            ],
        ),
        (
            "round-positive-tie",
            0x40_0000,
            0x10,
            [0x3f80_0000, 0x3380_0000, 0x3f80_0001],
            [
                0x3ff0_0000_0000_0000,
                0x3ca0_0000_0000_0000,
                0x3ff0_0000_0000_0001,
            ],
        ),
        (
            "round-negative-tie",
            0x80_0000,
            0x10,
            [0x3f80_0000, 0x3380_0000, 0x3f80_0000],
            [
                0x3ff0_0000_0000_0000,
                0x3ca0_0000_0000_0000,
                0x3ff0_0000_0000_0000,
            ],
        ),
        (
            "round-zero-tie",
            0xc0_0000,
            0x10,
            [0x3f80_0000, 0x3380_0000, 0x3f80_0000],
            [
                0x3ff0_0000_0000_0000,
                0x3ca0_0000_0000_0000,
                0x3ff0_0000_0000_0000,
            ],
        ),
        ("retain-input-subnormal", 0, 0, [1, 0, 1], [1, 0, 1]),
        (
            "flush-input-subnormal",
            0x100_0000,
            0x80,
            [1, 0, 0],
            [1, 0, 0],
        ),
        (
            "propagate-qnan",
            0,
            0,
            [0x7fc0_1234, 0x3f80_0000, 0x7fc0_1234],
            [
                0x7ff8_1234_5678_90ab,
                0x3ff0_0000_0000_0000,
                0x7ff8_1234_5678_90ab,
            ],
        ),
        (
            "default-qnan",
            0x200_0000,
            0,
            [0x7fc0_1234, 0x3f80_0000, 0x7fc0_0000],
            [
                0x7ff8_1234_5678_90ab,
                0x3ff0_0000_0000_0000,
                0x7ff8_0000_0000_0000,
            ],
        ),
        (
            "quiet-snan",
            0,
            1,
            [0x7f80_1234, 0x3f80_0000, 0x7fc0_1234],
            [
                0x7ff0_1234_5678_90ab,
                0x3ff0_0000_0000_0000,
                0x7ff8_1234_5678_90ab,
            ],
        ),
        (
            "default-snan",
            0x200_0000,
            1,
            [0x7f80_1234, 0x3f80_0000, 0x7fc0_0000],
            [
                0x7ff0_1234_5678_90ab,
                0x3ff0_0000_0000_0000,
                0x7ff8_0000_0000_0000,
            ],
        ),
    ] {
        for (word, [left, right, expected]) in [(super::VADD, single), (0xee31_0b02, double)] {
            let mut cpu = arm1176_cpu();
            cpu.regs[0] = control;
            cpu.vfp.dregs[0] = 0x0987_6543_210f_edcb;
            cpu.vfp.dregs[1] = left;
            cpu.vfp.dregs[2] = right;
            let mut memory = FlatMemory::new(4096, 0);
            let mut executor = Executor::new(&mut cpu, &mut memory);
            for raw in [0xeee1_0a10, word, 0xeef1_1a10, 0xeef6_2a10] {
                let result = executor.execute(&Aarch32Decoder::decode(raw).unwrap());
                assert!(
                    matches!(result, ExecResult::Continue),
                    "{name} {word:#x} {raw:#x}: {result:?}"
                );
            }
            let wanted_d0 = if word == super::VADD {
                0x0987_6543_0000_0000 | expected
            } else {
                expected
            };
            assert_eq!(cpu.vfp.dregs[0], wanted_d0, "{name} {word:#x}");
            assert_eq!(cpu.regs[1], control | status, "{name} {word:#x}");
            assert_eq!(cpu.regs[2], 0, "ARM1176 MVFR1 readback");
        }
    }
}

#[test]
fn arm1176_flush_uses_positive_zero_for_tiny_inputs_and_results() {
    const FZ: u32 = 1 << 24;
    for (multiply, divide, sqrt, sign, one, half, min_normal, infinity) in [
        (
            0xee21_0a02,
            0xee81_0a02,
            0xeeb1_0ac1,
            1 << 31,
            0x3f80_0000,
            0x3f00_0000,
            0x0080_0000,
            0x7f80_0000,
        ),
        (
            0xee21_0b02,
            0xee81_0b02,
            0xeeb1_0bc1,
            1 << 63,
            0x3ff0_0000_0000_0000,
            0x3fe0_0000_0000_0000,
            0x0010_0000_0000_0000,
            0x7ff0_0000_0000_0000,
        ),
    ] {
        for arm11 in [true, false] {
            let flush_zero = if arm11 { 0 } else { sign };
            for (name, raw, control, left, right, expected, status) in [
                ("input", multiply, FZ, sign | 1, one, flush_zero, 0x80),
                (
                    "divisor",
                    divide,
                    FZ,
                    one,
                    sign | 1,
                    flush_zero | infinity,
                    0x82,
                ),
                (
                    "output",
                    multiply,
                    FZ,
                    sign | min_normal,
                    half,
                    flush_zero,
                    8,
                ),
                ("explicit zero", multiply, FZ, sign, one, sign, 0),
                ("sticky UFC", multiply, FZ | 8, sign, one, sign, 0),
                ("sqrt", sqrt, FZ, sign | 1, 0, flush_zero, 0x80),
                (
                    "negated multiply result",
                    multiply | 0x40,
                    FZ,
                    min_normal,
                    half,
                    flush_zero,
                    8,
                ),
                ("gradual underflow", multiply, 0, sign | 1, one, sign | 1, 0),
            ] {
                let mut cpu = if arm11 {
                    arm1176_cpu()
                } else {
                    Armv7Cpu::new()
                };
                cpu.regs[0] = control;
                cpu.vfp.dregs[1] = left;
                cpu.vfp.dregs[2] = right;
                let mut memory = FlatMemory::new(4096, 0);
                let mut executor = Executor::new(&mut cpu, &mut memory);
                for raw in [0xeee1_0a10, raw, 0xeef1_1a10] {
                    let result = executor.execute(&Aarch32Decoder::decode(raw).unwrap());
                    assert!(
                        matches!(result, ExecResult::Continue),
                        "{raw:#x}: {result:?}"
                    );
                }
                assert_eq!(
                    cpu.vfp.dregs[0], expected,
                    "{name} {raw:#x} ARM1176={arm11}"
                );
                assert_eq!(
                    cpu.regs[1],
                    control | status,
                    "{name} {raw:#x} ARM1176={arm11}"
                );
                assert_eq!(cpu.vfp.dregs[1], left);
                assert_eq!(cpu.vfp.dregs[2], right);
            }
        }
    }
}

#[test]
fn arm1176_flush_sign_reaches_precision_conversion_and_short_vector_lanes() {
    const FZ: u32 = 1 << 24;
    for arm11 in [true, false] {
        for (instruction, input, signed_zero, status) in [
            (0xeeb7_0ac1, 0x8000_0001, 1u64 << 63, 0x80),
            (0xeeb7_0bc1, 0x8000_0000_0000_0001, 1u64 << 31, 0x80),
            (0xeeb7_0bc1, 0xb800_0000_0000_0000, 1u64 << 31, 8), // Narrow -2^-127.
        ] {
            let mut cpu = if arm11 {
                arm1176_cpu()
            } else {
                Armv7Cpu::new()
            };
            let mut memory = FlatMemory::new(4096, 0);
            cpu.regs[0] = FZ;
            cpu.vfp.dregs[1] = input;
            let mut executor = Executor::new(&mut cpu, &mut memory);
            for raw in [0xeee1_0a10, instruction, 0xeef1_1a10] {
                let result = executor.execute(&Aarch32Decoder::decode(raw).unwrap());
                assert!(
                    matches!(result, ExecResult::Continue),
                    "{raw:#x}: {result:?}"
                );
            }
            assert_eq!(cpu.vfp.dregs[0], if arm11 { 0 } else { signed_zero });
            assert_eq!(cpu.regs[1], FZ | status);
        }
    }

    let mut cpu = arm1176_cpu();
    let mut memory = FlatMemory::new(4096, 0);
    cpu.regs[0] = FZ | (1 << 16); // Two lanes, stride one.
    cpu.vfp.dregs[4] = u64::MAX;
    cpu.vfp.dregs[8] = 0x8080_0000_8000_0001;
    cpu.vfp.dregs[12] = 0x3f00_0000_3f80_0000;
    let mut executor = Executor::new(&mut cpu, &mut memory);
    for raw in [0xeee1_0a10, 0xee28_4a0c, 0xeef1_1a10] {
        let result = executor.execute(&Aarch32Decoder::decode(raw).unwrap());
        assert!(
            matches!(result, ExecResult::Continue),
            "{raw:#x}: {result:?}"
        );
    }
    assert_eq!(cpu.vfp.dregs[4], 0);
    assert_eq!(cpu.regs[1], FZ | (1 << 16) | 0x88);
}

#[test]
fn arm1176_negated_multiply_keeps_the_default_nan_positive() {
    const DN: u32 = 1 << 25;
    const FZ: u32 = 1 << 24;
    for (vnmul, vneg, sign, quiet, default_nan, one, infinity) in [
        (
            0xee21_0a42,
            0xeeb1_0a41,
            1u64 << 31,
            1u64 << 22,
            0x7fc0_0000,
            0x3f80_0000,
            0x7f80_0000,
        ),
        (
            0xee21_0b42,
            0xeeb1_0b41,
            1u64 << 63,
            1u64 << 51,
            0x7ff8_0000_0000_0000,
            0x3ff0_0000_0000_0000,
            0x7ff0_0000_0000_0000,
        ),
    ] {
        for arm11 in [true, false] {
            for control in [DN, DN | FZ, 0, FZ, 1] {
                // DDI0301H §18.5.3 and §§22.6–22.6.2. With IOE clear, an
                // invalid non-NaN product generates a Default NaN even with DN clear.
                let arithmetic_nan = |payload| match (control & DN != 0, arm11) {
                    (true, true) => default_nan,
                    (true, false) => default_nan | sign,
                    (false, _) => (default_nan | payload) ^ sign,
                };
                let invalid_product = if arm11 {
                    default_nan
                } else {
                    default_nan | sign
                };
                for (name, instruction, left, right, expected, status) in [
                    (
                        "canonical quiet NaN",
                        vnmul,
                        default_nan,
                        one,
                        arithmetic_nan(0),
                        0,
                    ),
                    (
                        "quiet NaN",
                        vnmul,
                        default_nan | 5,
                        one,
                        arithmetic_nan(5),
                        0,
                    ),
                    (
                        "signaling NaN",
                        vnmul,
                        (default_nan ^ quiet) | 9,
                        one,
                        arithmetic_nan(9),
                        1,
                    ),
                    (
                        "zero times infinity",
                        vnmul,
                        0,
                        infinity,
                        invalid_product,
                        1,
                    ),
                    (
                        "infinity times zero",
                        vnmul,
                        infinity,
                        sign,
                        invalid_product,
                        1,
                    ),
                    (
                        "subnormal times infinity",
                        vnmul,
                        1,
                        infinity,
                        if control & FZ != 0 {
                            invalid_product
                        } else {
                            infinity | sign
                        },
                        if control & FZ != 0 { 0x81 } else { 0 },
                    ),
                    ("finite product", vnmul, one, one, one | sign, 0),
                    (
                        "sign edit",
                        vneg,
                        default_nan | 5,
                        one,
                        default_nan | sign | 5,
                        0,
                    ),
                ] {
                    let mut cpu = if arm11 {
                        arm1176_cpu()
                    } else {
                        Armv7Cpu::new()
                    };
                    cpu.regs[0] = control;
                    cpu.vfp.dregs[1] = left;
                    cpu.vfp.dregs[2] = right;
                    let mut memory = FlatMemory::new(4096, 0);
                    let mut executor = Executor::new(&mut cpu, &mut memory);
                    let case = (name, arm11, control, instruction);
                    for raw in [0xeee1_0a10, instruction, 0xeef1_1a10] {
                        let result = executor.execute(&Aarch32Decoder::decode(raw).unwrap());
                        assert!(
                            matches!(result, ExecResult::Continue),
                            "{case:?}: {result:?}"
                        );
                    }
                    assert_eq!(cpu.vfp.dregs[0], expected, "{case:?}");
                    assert_eq!(cpu.regs[1], control | status, "{case:?}");
                }
            }
        }
    }
}

#[test]
fn fixed_to_half_flush_admission_changes_above_fourteen_fraction_bits() {
    for thumb in [false, true] {
        for (raw, fractional_bits) in [
            (0xeeba_0941, 14), // VCVT.F16.S16 S0, S0, #14
            (0xeeba_0960, 15), // VCVT.F16.S16 S0, S0, #15
            (0xeebb_09c9, 14), // VCVT.F16.U32 S0, S0, #14
            (0xeebb_09e8, 15), // VCVT.F16.U32 S0, S0, #15
        ] {
            for (support, control) in [(3, 0), (3, 1 << 24), (3, 1 << 19), (7, 0)] {
                let mut cpu = configured(thumb, support, control);
                cpu.vfp.fpscr = Fpscr::from_bits(control);
                cpu.vfp.write_s_bits(0, 1);
                let before = cpu.vfp.dregs;
                let insn = if thumb {
                    ThumbDecoder::decode_32bit(raw)
                } else {
                    Aarch32Decoder::decode(raw)
                }
                .unwrap();
                let result = Executor::new(&mut cpu, &mut FlatMemory::new(4096, 0)).execute(&insn);
                let context = (thumb, raw, support, control);
                if fractional_bits == 14 {
                    assert!(
                        matches!(result, ExecResult::Continue),
                        "{context:?}: {result:?}"
                    );
                    assert_eq!(cpu.vfp.read_h_bits(0), 0x0400, "{context:?}");
                    assert_eq!(cpu.vfp.fpscr.bits(), control, "{context:?}");
                } else if control & (1 << 19) != 0 {
                    assert!(
                        matches!(result, ExecResult::Continue),
                        "{context:?}: {result:?}"
                    );
                    assert_eq!(cpu.vfp.read_h_bits(0), 0, "{context:?}");
                    assert_eq!(cpu.vfp.fpscr.bits(), control | (1 << 3), "{context:?}");
                } else if support == 7 {
                    assert!(
                        matches!(result, ExecResult::Continue),
                        "{context:?}: {result:?}"
                    );
                    assert_eq!(cpu.vfp.read_h_bits(0), 0x0200, "{context:?}");
                    assert_eq!(cpu.vfp.fpscr.bits(), control, "{context:?}");
                } else {
                    assert!(
                        matches!(
                            result,
                            ExecResult::Exception(ExceptionType::UndefinedInstruction)
                        ),
                        "{context:?}: {result:?}"
                    );
                    assert_eq!(cpu.vfp.dregs, before, "{context:?}");
                    assert_eq!(cpu.vfp.fpscr.bits(), control, "{context:?}");
                }
            }
        }
    }
}

#[test]
fn scalar_mode_matrix_preserves_the_unsupported_instruction_frontier() {
    let cases = cases();
    let mut denied = 0;
    let mut completed = 0;
    for thumb in [false, true] {
        for support in 0..8 {
            for index in 0..64 {
                let control = controls(index);
                for case in cases.iter().filter(|case| case.kind == "scalar") {
                    let mut cpu = configured(thumb, support, control);
                    let before = serde_json::to_vec(&cpu).unwrap();
                    let mut memory = FlatMemory::new(4096, 0);
                    let result = execute(&mut cpu, case, &mut memory);
                    if supported(case, support, control) {
                        assert!(
                            matches!(result, ExecResult::Continue),
                            "{} thumb={thumb} support={support} control={control:#x}: {result:?}",
                            case.name
                        );
                        completed += 1;
                    } else {
                        assert!(
                            matches!(
                                result,
                                ExecResult::Exception(ExceptionType::UndefinedInstruction)
                            ),
                            "{} thumb={thumb} support={support} control={control:#x}: {result:?}",
                            case.name
                        );
                        assert_eq!(
                            serde_json::to_vec(&cpu).unwrap(),
                            before,
                            "{} thumb={thumb} support={support} control={control:#x}",
                            case.name
                        );
                        assert_eq!(memory.read_word(0x800).unwrap(), 0);
                        denied += 1;
                    }
                }
            }
        }
    }
    assert_eq!(denied + completed, 138_240);
    assert!(denied > 0 && completed > 0);
    eprintln!("scalar mode matrix: {completed} completed, {denied} precise bounces");
}

#[test]
fn restricted_vfp_controls_do_not_disable_storage_or_advanced_simd() {
    for thumb in [false, true] {
        for case in cases().iter().filter(|case| case.kind == "independent") {
            let mut cpu = configured(thumb, 0, 3 << 22);
            let mut memory = FlatMemory::new(4096, 0);
            let result = execute(&mut cpu, case, &mut memory);
            assert!(
                matches!(result, ExecResult::Continue),
                "{} thumb={thumb}: {result:?}",
                case.name
            );
        }
    }
}

#[test]
fn scalar_widening_converts_the_smallest_subnormal_with_any_rounding_mode() {
    for thumb in [false, true] {
        for round_capability in 0..16 {
            for round_mode in 0..4 {
                for (raw, source, wide, expected) in [
                    (0xeeb2_0a41, 0x0000_0001, false, 103 << 23), // VCVTB.F32.F16
                    (0xeeb2_0ac1, 0x0001_0000, false, 103 << 23), // VCVTT.F32.F16
                    (0xeeb2_0b41, 0x0000_0001, true, 999 << 52),  // VCVTB.F64.F16
                    (0xeeb2_0bc1, 0x0001_0000, true, 999 << 52),  // VCVTT.F64.F16
                    (0xeeb7_0ac1, 0x0000_0001, true, 874 << 52),  // VCVT.F64.F32
                ] {
                    // 2^-24 and 2^-149 are normal in the destination formats.
                    // Keep FZ off for the binary32 source. FPConvert ignores FZ16.
                    let mut cpu = configured(thumb, 6, (round_mode << 22) | (1 << 19));
                    cpu.vfp.mvfr0 |= round_capability << 28;
                    cpu.vfp.write_s_bits(2, source);
                    let fpscr = cpu.vfp.fpscr.bits();
                    let insn = if thumb {
                        ThumbDecoder::decode_32bit(raw)
                    } else {
                        Aarch32Decoder::decode(raw)
                    }
                    .unwrap();
                    let result =
                        Executor::new(&mut cpu, &mut FlatMemory::new(4096, 0)).execute(&insn);
                    let context = (thumb, round_capability, round_mode, raw);
                    assert!(
                        matches!(result, ExecResult::Continue),
                        "{context:?}: {result:?}"
                    );
                    let actual = if wide {
                        cpu.vfp.dregs[0]
                    } else {
                        u64::from(cpu.vfp.read_s_bits(0))
                    };
                    assert_eq!(actual, expected, "{context:?}");
                    assert_eq!(cpu.vfp.fpscr.bits(), fpscr, "{context:?}");
                }
            }
        }
    }
}

#[test]
fn scalar_i32_to_f64_is_independent_of_rounding_and_exception_capabilities() {
    let cases = cases();
    for name in ["vcvt_f64_s32", "vcvt_f64_u32"] {
        let case = cases.iter().find(|case| case.name == name).unwrap();
        for thumb in [false, true] {
            for trap in [0, 1, 15] {
                for round in 0..16 {
                    for mode in 0..4 {
                        for source in [0, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff] {
                            let mut cpu = configured(thumb, 0, 0);
                            cpu.vfp.mvfr0 =
                                (cpu.vfp.mvfr0 & !(15 << 12)) | (round << 28) | (trap << 12);
                            let fpscr = (mode << 22) | (0x9f00 * u32::from(trap == 1)) | 0x80;
                            cpu.vfp.fpscr = Fpscr::from_bits(fpscr);
                            cpu.vfp.write_s_bits(2, source);
                            let mut expected = cpu.vfp.dregs;
                            expected[0] = if name == "vcvt_f64_s32" {
                                f64::from(source as i32).to_bits()
                            } else {
                                f64::from(source).to_bits()
                            };
                            let result = execute(&mut cpu, case, &mut FlatMemory::new(4096, 0));
                            let context = (name, thumb, trap, round, mode, source);
                            assert!(
                                matches!(result, ExecResult::Continue),
                                "{context:?}: {result:?}"
                            );
                            assert_eq!(cpu.vfp.dregs, expected, "{context:?}");
                            assert_eq!(cpu.vfp.fpscr.bits(), fpscr, "{context:?}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn scalar_sign_and_select_do_not_require_a_trapping_capability() {
    const NEGATIVE_SNAN: u32 = 0xff80_0042;
    const POSITIVE_SNAN: u32 = 0x7f80_0021;
    const VADD: u32 = 0xee31_0a02; // VADD.F32 S0, S2, S4.
    for thumb in [false, true] {
        for trap in 0..16 {
            for (raw, expected) in [
                (0xeeb0_0ac1, NEGATIVE_SNAN & 0x7fff_ffff), // VABS.F32
                (0xeeb1_0a41, NEGATIVE_SNAN ^ 0x8000_0000), // VNEG.F32
                (0xfe01_0a02, NEGATIVE_SNAN),               // VSELEQ.F32
                (0xfe21_0a02, NEGATIVE_SNAN),               // VSELGE.F32
                (0xfe31_0a02, POSITIVE_SNAN),               // VSELGT.F32
                (0xfe11_0a02, POSITIVE_SNAN),               // VSELVS.F32
                (VADD, 0x7fc0_0000),
            ] {
                let mut cpu = configured(thumb, 7, 1 << 25);
                cpu.cpsr.z = true;
                cpu.cpsr.n = false;
                cpu.cpsr.v = false;
                cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !(15 << 12)) | (trap << 12);
                // Preserve a pre-existing cumulative flag. An enabled invalid
                // operation trap provides the arithmetic control.
                let fpscr = (1 << 25) | (1 << 7) | (u32::from(trap == 1) << 8);
                cpu.vfp.fpscr = Fpscr::from_bits(fpscr);
                cpu.vfp.write_s_bits(2, NEGATIVE_SNAN);
                cpu.vfp.write_s_bits(4, POSITIVE_SNAN);
                let before = cpu.vfp.dregs;
                let insn = if thumb {
                    ThumbDecoder::decode_32bit(raw)
                } else {
                    Aarch32Decoder::decode(raw)
                }
                .unwrap();
                let result = Executor::new(&mut cpu, &mut FlatMemory::new(4096, 0)).execute(&insn);
                let context = (thumb, trap, raw);
                if raw == VADD && trap != 0 {
                    if trap == 1 {
                        assert!(
                            matches!(
                                result,
                                ExecResult::Exception(ExceptionType::FloatingPoint(1))
                            ),
                            "{context:?}: {result:?}"
                        );
                    } else {
                        assert!(
                            matches!(result, ExecResult::Undefined),
                            "{context:?}: {result:?}"
                        );
                    }
                    assert_eq!(cpu.vfp.dregs, before, "{context:?}");
                    assert_eq!(cpu.vfp.fpscr.bits(), fpscr, "{context:?}");
                } else {
                    assert!(
                        matches!(result, ExecResult::Continue),
                        "{context:?}: {result:?}"
                    );
                    assert_eq!(cpu.vfp.read_s_bits(0), expected, "{context:?}");
                    assert_eq!(
                        cpu.vfp.fpscr.bits(),
                        fpscr | u32::from(raw == VADD),
                        "{context:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn restricted_capabilities_do_not_force_guest_fpscr_writes_or_reads() {
    let cases = cases();
    let write = cases.iter().find(|case| case.name == "vmsr").unwrap();
    let read = cases.iter().find(|case| case.name == "vmrs").unwrap();
    for thumb in [false, true] {
        for index in 0..64 {
            let value = 0xa800_009f | controls(index);
            let mut cpu = configured(thumb, 0, 0);
            let mut memory = FlatMemory::new(4096, 0);
            cpu.regs[1] = value;
            assert!(matches!(
                execute(&mut cpu, write, &mut memory),
                ExecResult::Continue
            ));
            assert_eq!(cpu.vfp.fpscr.bits(), value);
            assert!(matches!(
                execute(&mut cpu, read, &mut memory),
                ExecResult::Continue
            ));
            assert_eq!(cpu.regs[1], value);
        }
    }
}

#[test]
fn reserved_scalar_control_capabilities_precede_access_traps() {
    let cases = cases();
    let add = cases.iter().find(|case| case.name == "vadd_f32").unwrap();
    for thumb in [false, true] {
        for field in 0..3 {
            for reserved in 2..16 {
                let mut cpu = super::hyp();
                cpu.cpsr.t = thumb;
                cpu.cp15.hcptr = 1 << 10;
                match field {
                    0 => cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !(15 << 28)) | (reserved << 28),
                    1 => cpu.vfp.mvfr1 = (cpu.vfp.mvfr1 & !0xf0) | (reserved << 4),
                    2 => cpu.vfp.mvfr1 = (cpu.vfp.mvfr1 & !15) | reserved,
                    _ => unreachable!(),
                }
                let before = (
                    cpu.regs,
                    cpu.vfp.dregs,
                    cpu.vfp.fpscr.bits(),
                    cpu.cpsr.to_u32(),
                );
                let mut memory = FlatMemory::new(4096, 0);
                let result = execute(&mut cpu, add, &mut memory);
                assert!(
                    matches!(result, ExecResult::Undefined),
                    "field={field} value={reserved} thumb={thumb}: {result:?}"
                );
                assert_eq!(
                    (
                        cpu.regs,
                        cpu.vfp.dregs,
                        cpu.vfp.fpscr.bits(),
                        cpu.cpsr.to_u32()
                    ),
                    before
                );
            }
        }
    }
}

#[test]
fn access_traps_precede_the_selected_runtime_support_code_bounce() {
    let cases = cases();
    let add = cases.iter().find(|case| case.name == "vadd_f32").unwrap();
    for thumb in [false, true] {
        let mut cpu = super::hyp();
        cpu.cpsr.t = thumb;
        cpu.cp15.hcptr = 1 << 10;
        cpu.vfp.mvfr0 &= !(15 << 28);
        cpu.vfp.mvfr1 &= !0xff;
        cpu.vfp.fpscr = Fpscr::from_bits(3 << 22);
        let before = cpu.vfp.dregs;
        let result = execute(&mut cpu, add, &mut FlatMemory::new(4096, 0));
        assert!(
            matches!(
                result,
                ExecResult::FpAccessTrap {
                    target_el: 2,
                    undefined: true,
                    ..
                }
            ),
            "{result:?}"
        );
        assert_eq!(cpu.vfp.dregs, before);
    }
}

#[test]
fn failed_arm_predicate_suppresses_the_runtime_mode_check() {
    let mut cpu = configured(false, 0, 3 << 22);
    cpu.cpsr.z = true;
    let before = (
        cpu.regs,
        cpu.vfp.dregs,
        cpu.vfp.fpscr.bits(),
        cpu.cpsr.to_u32(),
    );
    let insn = Aarch32Decoder::decode(0x1e31_0a02).unwrap(); // VADDNE.F32 S0,S2,S4.
    let result = Executor::new(&mut cpu, &mut FlatMemory::new(4096, 0)).execute(&insn);
    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(
        (
            cpu.regs,
            cpu.vfp.dregs,
            cpu.vfp.fpscr.bits(),
            cpu.cpsr.to_u32()
        ),
        before
    );
}

#[test]
fn failed_thumb_predicate_suppresses_the_runtime_mode_check() {
    let mut cpu = configured(true, 0, 3 << 22);
    cpu.cpsr.z = true;
    cpu.cpsr.it_state = 0x18; // IT NE fails with Z=1.
    let before = serde_json::to_vec(&cpu).unwrap();
    let insn = ThumbDecoder::decode_32bit(0xee31_0a02).unwrap();
    let result = Executor::new(&mut cpu, &mut FlatMemory::new(4096, 0)).execute(&insn);
    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(serde_json::to_vec(&cpu).unwrap(), before);
}

#[test]
fn scalar_capability_reserved_values_do_not_disable_independent_operations() {
    for thumb in [false, true] {
        for case in cases().iter().filter(|case| case.kind == "independent") {
            let mut cpu = configured(thumb, 0, 3 << 22);
            cpu.vfp.mvfr0 |= 15 << 28;
            cpu.vfp.mvfr1 |= 0xff;
            let result = execute(&mut cpu, case, &mut FlatMemory::new(4096, 0));
            assert!(
                matches!(result, ExecResult::Continue),
                "{} thumb={thumb}: {result:?}",
                case.name
            );
        }
    }
}

#[test]
fn aarch32_lifter_retains_the_scalar_fp_interpreter_frontier() {
    use rax::smir::ir::types::SourceArch;
    use rax::smir::lift::aarch32::Aarch32Lifter;
    use rax::smir::lift::{LiftContext, LiftError, SmirLifter};
    for case in cases()
        .iter()
        .filter(|case| case.kind == "scalar" || case.name == "vmrs_fpsid")
    {
        let mut context = LiftContext::new(SourceArch::Aarch32);
        let result = Aarch32Lifter::new().lift_insn(0x100, &case.arm.to_le_bytes(), &mut context);
        assert!(
            matches!(result, Err(LiftError::Unsupported { .. })),
            "{}: {result:?}",
            case.name
        );
    }
}

#[test]
fn restricted_profiles_advertise_the_selected_support_code_subarchitecture() {
    let cases = cases();
    let read = cases.iter().find(|case| case.name == "vmrs_fpsid").unwrap();
    for thumb in [false, true] {
        for support in 0..8 {
            for raw in [0x4103_3070, 0x1234_5678, u32::MAX] {
                for index in 0..64 {
                    let mut cpu = configured(thumb, support, controls(index));
                    cpu.vfp.fpsid = raw;
                    let expected = if support == 7 {
                        raw
                    } else {
                        (raw & !0x007f_0000) | 0x0040_0000
                    };
                    let mut memory = FlatMemory::new(4096, 0);
                    assert!(matches!(
                        execute(&mut cpu, read, &mut memory),
                        ExecResult::Continue
                    ));
                    assert_eq!(
                        cpu.regs[0], expected,
                        "thumb={thumb} support={support} raw={raw:#x} control={index}"
                    );
                    assert_eq!(cpu.vfp.fpsid, raw);
                    assert!(format!("{:?}", cpu.vfp).contains(&format!("FPSID: {expected:08x}")));
                    assert_eq!(cpu.vfp.fpscr.bits(), 0xa800_009f | controls(index));
                }
            }
        }
    }
}

#[test]
fn mixed_width_profile_identity_and_restricted_modes_share_the_same_capabilities() {
    use rax::isa::arm::aarch64::AArch64Cpu;
    use rax::isa::arm::common::cpu::{ArmCpu, ArmError, CpuExit};
    use rax::isa::arm::common::sysreg::Aarch64SysRegEncoding;

    fn registers(cpu: &AArch64Cpu) -> Vec<u8> {
        let core: [u64; 31] = std::array::from_fn(|index| cpu.get_x(index as u8));
        let simd: [u128; 32] = std::array::from_fn(|index| cpu.get_simd(index as u8));
        serde_json::to_vec(&(
            cpu.export_sregs(),
            core,
            simd,
            cpu.fpcr_value(),
            cpu.fpsr_value(),
            cpu.get_pc(),
            cpu.pstate_bits(),
            cpu.instruction_count(),
        ))
        .unwrap()
    }

    for thumb in [false, true] {
        for support in 0..8 {
            for trapped in [false, true] {
                let mut cpu = super::mixed(super::VADD, thumb, 2, false, true);
                let mut state = cpu.export_sregs();
                let system = &mut state.execution.as_mut().unwrap().sysregs;
                system
                    .impl_defined
                    .insert(Aarch64SysRegEncoding::new(3, 4, 1, 1, 2).encode(), 0);
                let vfp = configured(thumb, support, 0).vfp;
                for (index, value) in [vfp.mvfr0, vfp.mvfr1, vfp.mvfr2].into_iter().enumerate() {
                    system.impl_defined.insert(
                        Aarch64SysRegEncoding::new(3, 0, 0, 3, index as u8).encode(),
                        u64::from(value),
                    );
                }
                cpu.import_sregs(&state).unwrap();
                cpu.set_fpcr_value(1 << 22);
                cpu.set_fpsr_value(0xa800_009f);
                let encode = |word: u32| {
                    if thumb {
                        [
                            ((word >> 16) as u16).to_le_bytes(),
                            (word as u16).to_le_bytes(),
                        ]
                        .concat()
                    } else {
                        word.to_le_bytes().to_vec()
                    }
                };
                cpu.write_memory(0x100, &encode(0xeef0_0a10)).unwrap(); // LLVM VMRS R0,FPSID.
                cpu.write_memory(0x104, &encode(super::VADD)).unwrap();
                assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
                assert_eq!(
                    cpu.get_x(0),
                    if support == 7 {
                        0x4103_3070
                    } else {
                        0x4140_3070
                    }
                );
                assert_eq!(cpu.get_pc(), 0x104);
                assert_eq!(cpu.instruction_count(), 1);
                if trapped {
                    let mut state = cpu.export_sregs();
                    state
                        .execution
                        .as_mut()
                        .unwrap()
                        .sysregs
                        .impl_defined
                        .insert(Aarch64SysRegEncoding::new(3, 4, 1, 1, 2).encode(), 1 << 10);
                    cpu.import_sregs(&state).unwrap();
                }
                let before = registers(&cpu);
                let result = cpu.step();
                if trapped {
                    assert!(
                        matches!(
                            result,
                            Err(ArmError::ArchitecturalException {
                                ec: 7,
                                target_el: Some(2),
                                ..
                            })
                        ),
                        "support={support} thumb={thumb}: {result:?}"
                    );
                    assert_eq!(registers(&cpu), before);
                } else if support != 7 {
                    assert!(
                        matches!(result, Err(ArmError::UndefinedInstruction(actual)) if actual == super::VADD),
                        "support={support} thumb={thumb}: {result:?}"
                    );
                    assert_eq!(registers(&cpu), before);
                } else {
                    assert_eq!(result.unwrap(), CpuExit::Continue);
                    assert_eq!(cpu.get_simd(0) as u32, 0x4040_0000);
                    assert_eq!(cpu.get_pc(), 0x108);
                    assert_eq!(cpu.instruction_count(), 2);
                }
            }
        }
    }
}

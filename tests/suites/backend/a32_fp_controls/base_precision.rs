//! Scalar MVFR0 precision and optional-operation admission.
use rax::isa::arm::aarch32::cp15::Cpacr;
use rax::isa::arm::decoder::{Aarch32Decoder, ThumbDecoder};
use rax::isa::arm::execution::{ArmMemory, FlatMemory};
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};

const CASES: &[(&str, u32, u32)] = &[
    ("single", 0xee300a00, 0xee300a00),
    ("double", 0xee300b00, 0xee300b00),
    ("pair_storage", 0xec421b10, 0xec421b10),
    ("double_load", 0xed900b00, 0xed900b00),
    ("double_store", 0xed800b00, 0xed800b00),
    ("double_register_move", 0xeeb00b40, 0xeeb00b40),
    ("single_to_double", 0xeeb70ac0, 0xeeb70ac0),
    ("double_to_single", 0xeeb70bc0, 0xeeb70bc0),
    ("divide_single", 0xee800a00, 0xee800a00),
    ("sqrt_single", 0xeeb10ac0, 0xeeb10ac0),
    ("constant_single", 0xeeb70a08, 0xeeb70a08),
    ("fixed_single", 0xeebe0aef, 0xeebe0aef),
    ("constant_double", 0xeeb70b08, 0xeeb70b08),
    ("fixed_double", 0xeebe0bef, 0xeebe0bef),
    ("divide_double", 0xee800b00, 0xee800b00),
    ("sqrt_double", 0xeeb10bc0, 0xeeb10bc0),
];

fn check(name: &str, mvfr0: u32, allowed: bool) {
    let &(_, arm, thumb) = CASES.iter().find(|&&(n, _, _)| n == name).unwrap();
    for is_thumb in [false, true] {
        for controls_denied in [false, true] {
            if allowed && controls_denied {
                continue;
            }
            let mut cpu = Armv7Cpu::new();
            cpu.vfp.mvfr0 = mvfr0;
            if mvfr0 == 0x1011_0021 {
                cpu.vfp.mvfr1 = 0x1100_0011;
            }
            if controls_denied {
                cpu.cp15.cpacr = Cpacr::from_bits(0);
                cpu.cp15.hcptr = 1 << 10;
                cpu.vfp.fpexc = 0;
            }
            cpu.cpsr.t = is_thumb;
            cpu.regs[0] = 0x400;
            cpu.regs[1] = 0xdead_beef;
            cpu.regs[2] = 0x1234_5678;
            cpu.regs[15] = 0x100;
            cpu.vfp.dregs.fill(0x3ff0_0000_3f80_0000);
            let before = (
                cpu.regs,
                cpu.vfp.dregs,
                cpu.vfp.fpscr.bits(),
                cpu.cpsr.to_u32(),
            );
            let mut memory = FlatMemory::new(4096, 0);
            let insn = if is_thumb {
                ThumbDecoder::decode_32bit(thumb)
            } else {
                Aarch32Decoder::decode(arm)
            }
            .unwrap();
            let result = Executor::new(&mut cpu, &mut memory).execute(&insn);
            if allowed {
                assert!(
                    matches!(result, ExecResult::Continue),
                    "{name} {mvfr0:#x} thumb={is_thumb}: {result:?}"
                );
            } else {
                assert!(
                    matches!(result, ExecResult::Undefined),
                    "{name} {mvfr0:#x} thumb={is_thumb}: {result:?}"
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
                assert!(
                    (0..4096)
                        .step_by(4)
                        .all(|a| memory.read_word(a).unwrap() == 0)
                );
            }
        }
    }
}

#[test]
fn single_only_profile_rejects_double_arithmetic_and_both_conversion_directions() {
    for name in [
        "double",
        "double_register_move",
        "single_to_double",
        "double_to_single",
        "constant_double",
        "fixed_double",
        "divide_double",
        "sqrt_double",
    ] {
        check(name, 0x1011_0021, false);
    }
}

#[test]
fn single_only_profile_retains_single_ops_and_raw_64_bit_storage() {
    for name in [
        "single",
        "pair_storage",
        "double_load",
        "double_store",
        "divide_single",
        "sqrt_single",
        "constant_single",
        "fixed_single",
    ] {
        check(name, 0x1011_0021, true);
    }
}

#[test]
fn vfp_v2_retains_arithmetic_but_rejects_v3_constants_and_fixed_conversions() {
    for (field, arithmetic, constant, fixed) in [
        (4, "single", "constant_single", "fixed_single"),
        (8, "double", "constant_double", "fixed_double"),
    ] {
        let v2 = (0x1011_0222 & !(15 << field)) | (1 << field);
        check(arithmetic, v2, true);
        check(constant, v2, false);
        check(fixed, v2, false);
        check(constant, 0x1011_0222, true);
        check(fixed, 0x1011_0222, true);
    }
}

#[test]
fn divide_and_square_root_require_their_own_supported_field_values() {
    for (field, names) in [
        (16, ["divide_single", "divide_double"]),
        (20, ["sqrt_single", "sqrt_double"]),
    ] {
        for value in [0, 1, 2, 15] {
            for name in names {
                check(
                    name,
                    (0x1011_0222 & !(15 << field)) | (value << field),
                    value == 1,
                );
            }
        }
    }
}

#[test]
fn absent_and_reserved_precision_fields_reject_before_effects() {
    for (field, name) in [(4, "single"), (8, "double")] {
        for value in [0, 3, 15] {
            check(
                name,
                (0x1011_0222 & !(15 << field)) | (value << field),
                false,
            );
        }
    }
}

#[test]
fn scalar_storage_needs_scalar_fp_but_not_double_arithmetic() {
    for name in ["pair_storage", "double_load", "double_store"] {
        check(name, 0x1011_0202, false);
        check(name, 0x1011_0021, true);
    }
}

#[test]
fn single_double_conversion_needs_both_precision_fields() {
    for name in ["single_to_double", "double_to_single"] {
        for mvfr0 in [0x1011_0202, 0x1011_0022, 0x1011_0232, 0x1011_0322] {
            check(name, mvfr0, false);
        }
        check(name, 0x1011_0222, true);
    }
}

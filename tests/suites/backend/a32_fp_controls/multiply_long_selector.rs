//! Arm DDI0597 ID032025: obligatory-zero polynomial/saturating long selectors.
use rax::isa::arm::aarch32::{cp15::Cpacr, cpu::ProcessorMode};
use rax::isa::arm::common::cpu::{ArmCpu, ArmError};
use rax::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, Mnemonic, ThumbDecoder};
use rax::isa::arm::execution::{ArmMemory, FlatMemory};
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};

// Each result is independently executed by the Cortex-A15 QEMU guest. The
// initial D0/D1 values are shared below, including the accumulation operands.
const CASES: [(u32, Mnemonic, u64, u64); 7] = [
    (
        0xf280_0e00,
        Mnemonic::VMULL,
        0x0005_0004_0001_0000,
        0x0015_0014_0011_0010,
    ),
    (
        0xf290_0900,
        Mnemonic::VQDMLAL,
        0x0718_1d0c_0304_0100,
        0x9b1f_8738_1266_a698,
    ),
    (
        0xf290_0b00,
        Mnemonic::VQDMLSL,
        0x06f3_ecfc_0300_0100,
        0x9a5a_36a8_1202_0658,
    ),
    (
        0xf290_0d00,
        Mnemonic::VQDMULL,
        0x0012_1808_0002_0000,
        0x0062_a848_0032_5020,
    ),
    (
        0xf2a0_0900,
        Mnemonic::VQDMLAL,
        0x0718_1d18_0b04_0100,
        0x9b1f_87c4_fac6_a698,
    ),
    (
        0xf2a0_0b00,
        Mnemonic::VQDMLSL,
        0x06f3_ecef_fb00_0100,
        0x9a5a_361b_29a2_0658,
    ),
    (
        0xf2a0_0d00,
        Mnemonic::VQDMULL,
        0x0012_1814_0802_0000,
        0x0062_a8d4_e892_5020,
    ),
];

fn encoded(raw: u32, thumb: bool) -> u32 {
    if thumb {
        (raw & 0x00ff_ffff) | 0xef00_0000 | (((raw >> 24) & 1) << 28)
    } else {
        raw
    }
}

fn decode(raw: u32, thumb: bool) -> DecodedInsn {
    if thumb {
        ThumbDecoder::decode_32bit(raw).unwrap()
    } else {
        Aarch32Decoder::decode(raw).unwrap()
    }
}

fn cpu(thumb: bool) -> Armv7Cpu {
    let mut cpu = Armv7Cpu::new();
    cpu.cpsr.t = thumb;
    cpu.regs[15] = 0x800;
    cpu.cp15.cpacr = Cpacr::from_bits(0x00f0_0000);
    cpu.vfp.fpexc = 1 << 30;
    for (index, register) in cpu.vfp.dregs.iter_mut().enumerate() {
        *register = 0x0706_0504_0302_0100 ^ (index as u64 * 0x0101_0101_0101_0101);
    }
    cpu.vfp.dregs[0] = 0x0706_0504_0302_0100;
    cpu.vfp.dregs[1] = 0x9abc_def0_1234_5678;
    cpu
}

#[test]
fn all_long_register_fields_obey_the_fixed_selector_and_destination_alignment() {
    let mut cases = 0;
    for (base, mnemonic, _, _) in CASES {
        for thumb in [false, true] {
            for selector in 0..2 {
                for d in 0..32 {
                    for n in 0..32 {
                        for m in 0..32 {
                            let raw = encoded(
                                base | (selector << 24)
                                    | ((d >> 4) << 22)
                                    | ((d & 15) << 12)
                                    | ((n >> 4) << 7)
                                    | ((n & 15) << 16)
                                    | ((m >> 4) << 5)
                                    | (m & 15),
                                thumb,
                            );
                            let expected = if selector == 0 && d & 1 == 0 {
                                mnemonic
                            } else {
                                Mnemonic::UNDEFINED
                            };
                            assert_eq!(decode(raw, thumb).mnemonic, expected, "raw={raw:08x}");
                            cases += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 917_504);
}

fn execute_unchanged(raw: u32, thumb: bool, denial: u8, skipped: bool) -> ExecResult {
    let mut cpu = cpu(thumb);
    if denial == 1 {
        cpu.cp15.cpacr = Cpacr::from_bits(0);
        cpu.vfp.fpexc = 0;
    } else if denial == 2 {
        cpu.cpsr.mode = ProcessorMode::Hyp as u8;
        cpu.cp15.scr = 1;
        cpu.cp15.nsacr = 1 << 10;
        cpu.cp15.hcptr = 1 << 10;
    }
    if skipped {
        cpu.cpsr.it_state = 0x18; // IT NE with Z=1.
        cpu.cpsr.z = true;
    }
    let before = (
        cpu.regs,
        cpu.vfp.dregs,
        cpu.vfp.fpscr.bits(),
        cpu.vfp.fpexc,
        cpu.cpsr.to_u32(),
    );
    let mut memory = FlatMemory::new(4096, 0);
    let result = Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb));
    assert_eq!(
        (
            cpu.regs,
            cpu.vfp.dregs,
            cpu.vfp.fpscr.bits(),
            cpu.vfp.fpexc,
            cpu.cpsr.to_u32(),
        ),
        before,
        "raw={raw:08x}, denial={denial}, skipped={skipped}"
    );
    assert!(
        (0..4096)
            .step_by(4)
            .all(|address| memory.read_word(address).unwrap() == 0)
    );
    result
}

#[test]
fn reserved_long_selectors_precede_access_denials_without_architectural_effects() {
    for (base, _, _, _) in CASES {
        for thumb in [false, true] {
            let raw = encoded(base | (1 << 24), thumb);
            for denial in 0..3 {
                assert!(
                    matches!(
                        execute_unchanged(raw, thumb, denial, false),
                        ExecResult::Undefined
                    ),
                    "raw={raw:08x}, denial={denial}"
                );
            }
        }
    }
}

#[test]
fn failed_thumb_conditions_suppress_reserved_long_selector_faults() {
    for (base, _, _, _) in CASES {
        for denial in 0..3 {
            let raw = encoded(base | (1 << 24), true);
            assert!(matches!(
                execute_unchanged(raw, true, denial, true),
                ExecResult::Continue
            ));
        }
    }
}

#[test]
fn mixed_width_reserved_long_forms_remain_undefined_before_higher_el_fp_traps() {
    for (base, _, _, _) in CASES {
        for thumb in [false, true] {
            let raw = encoded(base | (1 << 24), thumb);
            let mut cpu = super::mixed(raw, thumb, 2, false, true);
            let system = cpu.export_sregs();
            let vectors: Vec<_> = (0..32).map(|id| cpu.get_simd(id)).collect();
            assert!(
                matches!(cpu.step(), Err(ArmError::UndefinedInstruction(value)) if value == raw)
            );
            assert_eq!(cpu.export_sregs(), system);
            assert_eq!(
                (0..32).map(|id| cpu.get_simd(id)).collect::<Vec<_>>(),
                vectors
            );
            assert_eq!(cpu.get_pc(), 0x100);
            assert_eq!(cpu.instruction_count(), 0);
        }
    }
}

#[test]
fn legal_long_forms_preserve_the_independent_qemu_results_and_other_registers() {
    for (base, mnemonic, low, high) in CASES {
        for thumb in [false, true] {
            let mut cpu = cpu(thumb);
            let mut expected = cpu.vfp.dregs;
            expected[0] = low;
            expected[1] = high;
            let raw = encoded(base, thumb);
            let instruction = decode(raw, thumb);
            assert_eq!(instruction.mnemonic, mnemonic);
            let mut memory = FlatMemory::new(4096, 0);
            assert!(matches!(
                Executor::new(&mut cpu, &mut memory).execute(&instruction),
                ExecResult::Continue
            ));
            assert_eq!(cpu.vfp.dregs, expected, "raw={raw:08x}");
            assert_eq!(cpu.vfp.fpscr.bits(), 0, "raw={raw:08x}");
        }
    }
}

#[test]
fn ordinary_integer_long_neighbors_retain_signed_and_unsigned_semantics() {
    for thumb in [false, true] {
        for unsigned in 0..2 {
            for size in 0..3 {
                for opcode in [8, 10, 12] {
                    let bits = 8 << size;
                    let wide = bits * 2;
                    let mask = (1u128 << wide) - 1;
                    let mut cpu = cpu(thumb);
                    cpu.vfp.dregs[2] = 0x8001_7fff_00fe_55aa;
                    cpu.vfp.dregs[4] = 0xff00_0180_7fff_5580;
                    let mut expected = cpu.vfp.dregs;
                    let accumulator = u128::from(expected[0]) | (u128::from(expected[1]) << 64);
                    let mut result = 0u128;
                    for lane in 0..64 / bits {
                        let operand = |value: u64| {
                            let value = (value >> (lane * bits)) & ((1u64 << bits) - 1);
                            if unsigned != 0 {
                                i128::from(value)
                            } else {
                                (i128::from(value) << (128 - bits)) >> (128 - bits)
                            }
                        };
                        let product = (operand(expected[2]) * operand(expected[4])) as u128 & mask;
                        let old = (accumulator >> (lane * wide)) & mask;
                        let value = match opcode {
                            8 => old.wrapping_add(product),
                            10 => old.wrapping_sub(product),
                            _ => product,
                        } & mask;
                        result |= value << (lane * wide);
                    }
                    expected[0] = result as u64;
                    expected[1] = (result >> 64) as u64;
                    let raw = encoded(
                        0xf280_0004 | (unsigned << 24) | (size << 20) | (2 << 16) | (opcode << 8),
                        thumb,
                    );
                    let mut memory = FlatMemory::new(4096, 0);
                    assert!(matches!(
                        Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb)),
                        ExecResult::Continue
                    ));
                    assert_eq!(cpu.vfp.dregs, expected, "raw={raw:08x}");
                    assert_eq!(cpu.vfp.fpscr.bits(), 0);
                }
            }
        }
    }
}

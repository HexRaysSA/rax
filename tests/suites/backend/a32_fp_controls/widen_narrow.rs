//! DDI0597 VSHLL/VMOVL and narrowing fixed fields, before FP access.
use rax::isa::arm::aarch32::{cp15::Cpacr, cpu::ProcessorMode, vfp::Fpscr};
use rax::isa::arm::common::cpu::{ArmCpu, ArmError};
use rax::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, ThumbDecoder};
use rax::isa::arm::execution::FlatMemory;
use rax::isa::arm::{Armv7Cpu, ExceptionType, ExecResult, Executor};
use rax::smir::ir::types::SourceArch;
use rax::smir::lift::aarch32::Aarch32Lifter;
use rax::smir::lift::thumb::ThumbLifter;
use rax::smir::lift::{LiftContext, LiftError, SmirLifter};

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

fn registers(d: u32, m: u32) -> u32 {
    ((d >> 4) << 22) | ((d & 15) << 12) | ((m >> 4) << 5) | (m & 15)
}

fn widen(bits: u32, count: u32, unsigned: u32, d: u32, m: u32) -> u32 {
    if count == bits {
        let size = match bits {
            8 => 0,
            16 => 1,
            32 => 2,
            _ => unreachable!(),
        };
        0xf3b2_0300 | (size << 18) | registers(d, m)
    } else {
        0xf280_0a10 | (unsigned << 24) | ((bits + count) << 16) | registers(d, m)
    }
}

fn cpu(thumb: bool, denial: u8) -> Armv7Cpu {
    let mut cpu = Armv7Cpu::new();
    cpu.cpsr.t = thumb;
    cpu.regs[15] = 0x800;
    cpu.cp15.cpacr = Cpacr::from_bits(0x00f0_0000);
    cpu.vfp.fpexc = 1 << 30;
    cpu.vfp.fpscr = Fpscr::from_bits(0x0800_0011);
    for (id, register) in cpu.vfp.dregs.iter_mut().enumerate() {
        *register = 0x9abc_def0_1234_5678u64.rotate_left(id as u32);
    }
    if denial == 1 {
        cpu.cp15.cpacr = Cpacr::from_bits(0);
    } else if denial == 2 {
        cpu.cpsr.mode = ProcessorMode::Hyp as u8;
        cpu.cp15.scr = 1;
        cpu.cp15.nsacr = 1 << 10;
        cpu.cp15.hcptr = 1 << 10;
    }
    cpu
}

fn reserved() -> Vec<u32> {
    let mut words = Vec::new();
    for op in [8, 9, 10] {
        for u in 0..2 {
            for immediate in [8, 16, 32] {
                for low_bit in 0..2 {
                    words.push(
                        0xf280_0012
                            | (u << 24)
                            | (immediate << 16)
                            | (op << 8)
                            | (1 << 7)
                            | (low_bit << 6),
                    );
                }
            }
        }
    }
    for u in 0..2 {
        for immediate in [8, 16, 32] {
            words.push(0xf280_0a52 | (u << 24) | (immediate << 16));
        }
    }
    words.push(0xf3be_0302); // Maximum-count VSHLL: size=3 is reserved.
    words
}

#[test]
fn widening_fields_admit_all_counts_and_reject_fixed_bits_or_odd_destinations() {
    for thumb in [false, true] {
        for u in 0..2 {
            for immediate in 8..64 {
                for fixed in 0..4 {
                    for d in 0..32 {
                        for m in 0..32 {
                            let raw = encoded(
                                0xf280_0a10
                                    | (u << 24)
                                    | (immediate << 16)
                                    | (fixed << 6)
                                    | registers(d, m),
                                thumb,
                            );
                            let expected = if fixed != 0 || d & 1 != 0 {
                                "udf"
                            } else if [8, 16, 32].contains(&immediate) {
                                "vmovl"
                            } else {
                                "vshll"
                            };
                            assert_eq!(
                                decode(raw, thumb).mnemonic.as_str(),
                                expected,
                                "raw={raw:08x}"
                            );
                        }
                    }
                }
            }
        }
        for size in 0..4 {
            for d in 0..32 {
                for m in 0..32 {
                    let raw = encoded(0xf3b2_0300 | (size << 18) | registers(d, m), thumb);
                    assert_eq!(
                        decode(raw, thumb).mnemonic.as_str(),
                        if size == 3 || d & 1 != 0 {
                            "udf"
                        } else {
                            "vshll"
                        },
                        "raw={raw:08x}"
                    );
                }
            }
        }
    }
}

#[test]
fn narrowing_fixed_bit_and_source_alignment_obey_every_immediate() {
    for thumb in [false, true] {
        for (op, u, rounding, mnemonic) in [
            (8, 0, 0, "vshrn"),
            (8, 0, 1, "vrshrn"),
            (8, 1, 0, "vqshrun"),
            (8, 1, 1, "vqrshrun"),
            (9, 0, 0, "vqshrn"),
            (9, 0, 1, "vqrshrn"),
            (9, 1, 0, "vqshrn"),
            (9, 1, 1, "vqrshrn"),
        ] {
            for immediate in 8..64 {
                for l in 0..2 {
                    for d in 0..32 {
                        for m in 0..32 {
                            let raw = encoded(
                                0xf280_0010
                                    | (u << 24)
                                    | (immediate << 16)
                                    | (op << 8)
                                    | (l << 7)
                                    | (rounding << 6)
                                    | registers(d, m),
                                thumb,
                            );
                            assert_eq!(
                                decode(raw, thumb).mnemonic.as_str(),
                                if l != 0 || m & 1 != 0 {
                                    "udf"
                                } else {
                                    mnemonic
                                },
                                "raw={raw:08x}"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn related_modified_immediates_reach_their_own_allocation() {
    for thumb in [false, true] {
        for immediate in 0..8 {
            for cmode in 0..16 {
                for op in 0..2 {
                    if cmode == 15 && op == 1 {
                        continue;
                    }
                    for q in 0..2 {
                        for d in 0..32 {
                            let raw = encoded(
                                0xf280_0010
                                    | (immediate << 16)
                                    | (cmode << 8)
                                    | (q << 6)
                                    | (op << 5)
                                    | registers(d, 0),
                                thumb,
                            );
                            let expected = if q != 0 && d & 1 != 0 {
                                "udf"
                            } else if cmode >= 14 {
                                "vmov"
                            } else if cmode >= 12 || cmode & 1 == 0 {
                                if op == 0 { "vmov" } else { "vmvn" }
                            } else if op == 0 {
                                "vorr"
                            } else {
                                "vbic"
                            };
                            assert_eq!(
                                decode(raw, thumb).mnemonic.as_str(),
                                expected,
                                "raw={raw:08x}"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn all_legal_widening_counts_match_integer_formulas_with_source_aliases() {
    for thumb in [false, true] {
        for bits in [8, 16, 32] {
            for u in 0..2 {
                for count in 0..=bits {
                    for (d, m) in [(0, 0), (0, 1), (2, 3), (30, 31)] {
                        for pattern in [0, u64::MAX, 0x8001_7fff_0706_0505] {
                            let mut cpu = cpu(thumb, 0);
                            cpu.vfp.dregs[m as usize] = pattern;
                            let mut expected = cpu.vfp.dregs;
                            let mask = (1u128 << bits) - 1;
                            let wide_mask = (1u128 << (bits * 2)) - 1;
                            let mut packed = 0u128;
                            for lane in 0..64 / bits {
                                let mut value =
                                    ((u128::from(pattern) >> (lane * bits)) & mask) as i128;
                                if u == 0 && value & (1i128 << (bits - 1)) != 0 {
                                    value -= 1i128 << bits;
                                }
                                packed |=
                                    (((value << count) as u128) & wide_mask) << (lane * 2 * bits);
                            }
                            expected[d as usize] = packed as u64;
                            expected[d as usize + 1] = (packed >> 64) as u64;
                            let raw = encoded(widen(bits, count, u, d, m), thumb);
                            let mut memory = FlatMemory::new(32, 0);
                            let result =
                                Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb));
                            assert!(
                                matches!(result, ExecResult::Continue),
                                "raw={raw:08x}: {result:?}"
                            );
                            assert_eq!(
                                cpu.vfp.dregs, expected,
                                "raw={raw:08x}, source={pattern:016x}"
                            );
                            assert_eq!(cpu.vfp.fpscr.bits(), 0x0800_0011);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn reserved_narrow_widen_forms_precede_fp_access_without_architectural_effects() {
    for word in reserved() {
        for thumb in [false, true] {
            let raw = encoded(word, thumb);
            for denial in 0..3 {
                let mut cpu = cpu(thumb, denial);
                let before = (
                    cpu.regs,
                    cpu.vfp.dregs,
                    cpu.vfp.fpscr.bits(),
                    cpu.vfp.fpexc,
                    cpu.cpsr.to_u32(),
                );
                let mut memory = FlatMemory::new(32, 0);
                assert!(
                    matches!(
                        Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb)),
                        ExecResult::Undefined
                    ),
                    "raw={raw:08x}, denial={denial}"
                );
                assert_eq!(
                    (
                        cpu.regs,
                        cpu.vfp.dregs,
                        cpu.vfp.fpscr.bits(),
                        cpu.vfp.fpexc,
                        cpu.cpsr.to_u32()
                    ),
                    before
                );
            }
        }
    }
}

#[test]
fn failed_thumb_it_suppresses_reserved_narrow_widen_faults() {
    for word in reserved() {
        for denial in 0..3 {
            let mut cpu = cpu(true, denial);
            cpu.cpsr.it_state = 0x18;
            cpu.cpsr.z = true;
            let before = cpu.vfp.dregs;
            let mut memory = FlatMemory::new(32, 0);
            let raw = encoded(word, true);
            assert!(matches!(
                Executor::new(&mut cpu, &mut memory).execute(&decode(raw, true)),
                ExecResult::Continue
            ));
            assert_eq!(cpu.vfp.dregs, before);
            assert_eq!(cpu.vfp.fpscr.bits(), 0x0800_0011);
        }
    }
}

#[test]
fn mixed_width_reserved_forms_are_undefined_but_legal_widening_takes_fp_traps() {
    for thumb in [false, true] {
        for word in reserved() {
            let raw = encoded(word, thumb);
            let mut cpu = super::mixed(raw, thumb, 2, false, true);
            let system = cpu.export_sregs();
            let vector = cpu.get_simd(0);
            assert!(
                matches!(cpu.step(), Err(ArmError::UndefinedInstruction(value)) if value == raw),
                "raw={raw:08x}"
            );
            assert_eq!(cpu.export_sregs(), system);
            assert_eq!(cpu.get_simd(0), vector);
            assert_eq!(cpu.get_pc(), 0x100);
            assert_eq!(cpu.instruction_count(), 0);
        }
        for bits in [8, 16, 32] {
            for count in [0, 1, bits] {
                let raw = encoded(widen(bits, count, 0, 0, 2), thumb);
                let mut cpu = super::mixed(raw, thumb, 2, false, true);
                let vector = cpu.get_simd(0);
                assert!(
                    matches!(
                        cpu.step(),
                        Err(ArmError::ArchitecturalException {
                            ec: 7,
                            target_el: Some(2),
                            ..
                        })
                    ),
                    "raw={raw:08x}"
                );
                assert_eq!(cpu.get_simd(0), vector);
                assert_eq!(cpu.get_pc(), 0x100);
                assert_eq!(cpu.instruction_count(), 0);
            }
        }
    }
}

#[test]
fn legal_widening_obeys_cpacr_denial_and_remains_outside_scalar_native_admission() {
    for thumb in [false, true] {
        for bits in [8, 16, 32] {
            for count in [0, 1, bits] {
                let raw = encoded(widen(bits, count, 0, 0, 2), thumb);
                let mut cpu = cpu(thumb, 1);
                let before = cpu.vfp.dregs;
                let mut memory = FlatMemory::new(32, 0);
                assert!(
                    matches!(
                        Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb)),
                        ExecResult::Exception(ExceptionType::UndefinedInstruction)
                    ),
                    "raw={raw:08x}"
                );
                assert_eq!(cpu.vfp.dregs, before);
                let bytes = if thumb {
                    [
                        ((raw >> 16) as u16).to_le_bytes(),
                        (raw as u16).to_le_bytes(),
                    ]
                    .concat()
                } else {
                    raw.to_le_bytes().to_vec()
                };
                let result = if thumb {
                    ThumbLifter::new().lift_insn(
                        0x100,
                        &bytes,
                        &mut LiftContext::new(SourceArch::Thumb),
                    )
                } else {
                    Aarch32Lifter::new().lift_insn(
                        0x100,
                        &bytes,
                        &mut LiftContext::new(SourceArch::Aarch32),
                    )
                };
                assert!(
                    matches!(result, Err(LiftError::Unsupported { addr: 0x100, .. })),
                    "raw={raw:08x}: {result:?}"
                );
            }
        }
    }
}

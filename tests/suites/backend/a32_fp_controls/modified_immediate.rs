//! Arm ASL modified-immediate allocation, expansion, and access priority.
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

fn literal(cmode: u32, op: u32, value: u32, q: u32, d: u32) -> u32 {
    0xf280_0010
        | ((value >> 7) << 24)
        | (((value >> 4) & 7) << 16)
        | ((d >> 4) << 22)
        | ((d & 15) << 12)
        | (cmode << 8)
        | (q << 6)
        | (op << 5)
        | (value & 15)
}

fn decode(raw: u32, thumb: bool) -> DecodedInsn {
    if thumb {
        ThumbDecoder::decode_32bit(raw).unwrap()
    } else {
        Aarch32Decoder::decode(raw).unwrap()
    }
}

fn mnemonic(cmode: u32, op: u32) -> Option<&'static str> {
    match (cmode, op) {
        (15, 1) => None,
        (14 | 15, _) => Some("vmov"),
        (12 | 13, 0) => Some("vmov"),
        (12 | 13, 1) => Some("vmvn"),
        (_, 0) => Some(if cmode & 1 == 0 { "vmov" } else { "vorr" }),
        (_, 1) => Some(if cmode & 1 == 0 { "vmvn" } else { "vbic" }),
        _ => unreachable!(),
    }
}

// AdvSIMDExpandImm's element placement, independent of executor helpers.
fn expanded(cmode: u32, op: u32, value: u32) -> u64 {
    match cmode {
        0..=7 => (u64::from(value) << (8 * (cmode / 2))) * 0x0000_0001_0000_0001,
        8..=11 => (u64::from(value) << (8 * ((cmode - 8) / 2))) * 0x0001_0001_0001_0001,
        12 => (u64::from(value) * 256 + 255) * 0x0000_0001_0000_0001,
        13 => (u64::from(value) * 65536 + 65535) * 0x0000_0001_0000_0001,
        14 if op == 0 => u64::from(value) * 0x0101_0101_0101_0101,
        14 => (0..8).fold(0, |bits, byte| {
            bits | (if value & (1 << byte) != 0 { 255 } else { 0 } << (8 * byte))
        }),
        15 => {
            let bit6 = (value >> 6) & 1;
            let bits = ((value & 128) << 24)
                | ((1 - bit6) << 30)
                | ((bit6 * 31) << 25)
                | ((value & 63) << 19);
            u64::from(bits) * 0x0000_0001_0000_0001
        }
        _ => unreachable!(),
    }
}

fn cpu(thumb: bool, denial: u8) -> Armv7Cpu {
    let mut cpu = Armv7Cpu::new();
    cpu.cpsr.t = thumb;
    cpu.regs[15] = 0x800;
    cpu.cp15.cpacr = Cpacr::from_bits(0x00f0_0000);
    cpu.vfp.fpexc = 1 << 30;
    cpu.vfp.fpscr = Fpscr::from_bits(0x0800_0011);
    for (index, register) in cpu.vfp.dregs.iter_mut().enumerate() {
        *register = 0x9abc_def0_1234_5678u64.rotate_left(index as u32);
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
    for immediate in [8, 16, 32, 63] {
        for high_literal in 0..2 {
            for op in 0..2 {
                for q in 0..2 {
                    words.push(
                        0xf280_0b12
                            | (immediate << 16)
                            | (high_literal << 24)
                            | (op << 5)
                            | (q << 6),
                    );
                }
            }
        }
    }
    words
}

#[test]
fn canonical_literals_admit_all_bytes_modes_lengths_and_registers() {
    for thumb in [false, true] {
        for cmode in 0..16 {
            for op in 0..2 {
                let Some(name) = mnemonic(cmode, op) else {
                    continue;
                };
                for value in 0..256 {
                    for q in 0..2 {
                        for d in 0..32 {
                            let raw = encoded(literal(cmode, op, value, q, d), thumb);
                            assert_eq!(
                                decode(raw, thumb).mnemonic.as_str(),
                                if q != 0 && d & 1 != 0 { "udf" } else { name },
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
fn every_reserved_high_prefix_rejects_before_modified_immediate_allocation() {
    for thumb in [false, true] {
        for immediate in 8..64 {
            for high_literal in 0..2 {
                for op in 0..2 {
                    for q in 0..2 {
                        for d in 0..32 {
                            for low_literal in 0..16 {
                                let raw = encoded(
                                    literal(11, op, high_literal << 7 | low_literal, q, d)
                                        | (immediate << 16),
                                    thumb,
                                );
                                assert_eq!(
                                    decode(raw, thumb).mnemonic.as_str(),
                                    "udf",
                                    "raw={raw:08x}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn canonical_literal_execution_matches_all_expansions_and_preserves_other_state() {
    for thumb in [false, true] {
        for cmode in 0..16 {
            for op in 0..2 {
                let Some(name) = mnemonic(cmode, op) else {
                    continue;
                };
                for value in 0..256 {
                    for q in 0..2 {
                        for d in [0, 16, 30, 31] {
                            if q != 0 && d & 1 != 0 {
                                continue;
                            }
                            let raw = encoded(literal(cmode, op, value, q, d), thumb);
                            let mut cpu = cpu(thumb, 0);
                            let gprs = cpu.regs;
                            let mut expected = cpu.vfp.dregs;
                            let immediate = expanded(cmode, op, value);
                            for destination in d..d + q + 1 {
                                let old = expected[destination as usize];
                                expected[destination as usize] = match name {
                                    "vmov" => immediate,
                                    "vmvn" => !immediate,
                                    "vorr" => old | immediate,
                                    "vbic" => old & !immediate,
                                    _ => unreachable!(),
                                };
                            }
                            let mut memory = FlatMemory::new(32, 0);
                            let result =
                                Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb));
                            assert!(
                                matches!(result, ExecResult::Continue),
                                "{raw:08x}: {result:?}"
                            );
                            assert_eq!(cpu.vfp.dregs, expected, "raw={raw:08x}");
                            assert_eq!(cpu.regs, gprs, "raw={raw:08x}");
                            assert_eq!(cpu.vfp.fpscr.bits(), 0x0800_0011, "raw={raw:08x}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn reserved_prefixes_are_undefined_before_fp_access_without_effects() {
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
                let result = Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb));
                assert!(
                    matches!(result, ExecResult::Undefined),
                    "{raw:08x}, denial={denial}: {result:?}"
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
fn failed_thumb_it_suppresses_reserved_prefix_faults() {
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
fn mixed_width_reserved_prefixes_do_not_select_fp_traps_or_retire() {
    for word in reserved() {
        for thumb in [false, true] {
            let raw = encoded(word, thumb);
            let mut cpu = super::mixed(raw, thumb, 2, false, true);
            let system = cpu.export_sregs();
            let vectors: Vec<_> = (0..32).map(|reg| cpu.get_simd(reg)).collect();
            let gprs: Vec<_> = (0..31).map(|reg| cpu.get_gpr(reg)).collect();
            assert!(
                matches!(cpu.step(), Err(ArmError::UndefinedInstruction(value)) if value == raw),
                "raw={raw:08x}"
            );
            assert_eq!(cpu.export_sregs(), system);
            assert_eq!(
                (0..32).map(|reg| cpu.get_simd(reg)).collect::<Vec<_>>(),
                vectors
            );
            assert_eq!(
                (0..31).map(|reg| cpu.get_gpr(reg)).collect::<Vec<_>>(),
                gprs
            );
            assert_eq!(cpu.get_pc(), 0x100);
            assert_eq!(cpu.instruction_count(), 0);
        }
    }
}

#[test]
fn canonical_literals_keep_fp_access_controls_and_precise_native_rejection() {
    for thumb in [false, true] {
        for cmode in 0..16 {
            for op in 0..2 {
                if mnemonic(cmode, op).is_none() {
                    continue;
                }
                let raw = encoded(literal(cmode, op, 0x82, 1, 0), thumb);
                let mut cpu = cpu(thumb, 1);
                let before = cpu.vfp.dregs;
                let mut memory = FlatMemory::new(32, 0);
                assert!(matches!(
                    Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb)),
                    ExecResult::Exception(ExceptionType::UndefinedInstruction)
                ));
                assert_eq!(cpu.vfp.dregs, before);
                let mut mixed = super::mixed(raw, thumb, 2, false, true);
                assert!(
                    matches!(
                        mixed.step(),
                        Err(ArmError::ArchitecturalException {
                            ec: 7,
                            target_el: Some(2),
                            ..
                        })
                    ),
                    "raw={raw:08x}"
                );
                assert_eq!(mixed.get_pc(), 0x100);
                assert_eq!(mixed.instruction_count(), 0);
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

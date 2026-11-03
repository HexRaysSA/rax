//! Decode-time structure-list/base admission precedes AdvSIMD access checks.
use rax::isa::arm::aarch32::cp15::Cpacr;
use rax::isa::arm::aarch32::cpu::ProcessorMode;
use rax::isa::arm::common::cpu::{ArmCpu, ArmError};
use rax::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, Mnemonic, ThumbDecoder};
use rax::isa::arm::execution::{ArmMemory, FlatMemory};
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};

// The second field is the last permitted first D register, derived from the
// VLDn/VSTn decode rules in the archived Arm instruction ASL. The table includes
// consecutive lists, spaced lists, the two-register VLD2 form, and all widths.
fn forms() -> Vec<(u32, u32)> {
    let mut cases = Vec::new();
    for (kind, last) in [
        (0b0111, 31),
        (0b1010, 30),
        (0b0110, 29),
        (0b0010, 28),
        (0b1000, 30),
        (0b1001, 29),
        (0b0011, 28),
        (0b0100, 29),
        (0b0101, 27),
        (0b0000, 28),
        (0b0001, 25),
    ] {
        for load in [0, 1] {
            let sizes = if matches!(kind, 0b0111 | 0b1010 | 0b0110 | 0b0010) {
                0..4 // VLD1/VST1 additionally allocate 64-bit elements.
            } else {
                0..3
            };
            for size in sizes {
                cases.push((0xf400_000f | (load << 21) | (kind << 8) | (size << 6), last));
            }
        }
    }
    for streams in 1..=4 {
        // Size and index_align select the first/last element and both legal
        // register strides. Byte elements always have unit register stride.
        for (size, index_align, stride) in [
            (0, 0, 1),
            (0, 14, 1),
            (1, 0, 1),
            (1, 12, 1),
            (1, 2, 2),
            (1, 14, 2),
            (2, 0, 1),
            (2, 8, 1),
            (2, 4, 2),
            (2, 12, 2),
        ] {
            if streams == 1 && stride == 2 {
                continue; // These bits are reserved for a single stream.
            }
            for load in [0, 1] {
                cases.push((
                    0xf480_000f
                        | (load << 21)
                        | ((streams - 1) << 8)
                        | (size << 10)
                        | (index_align << 4),
                    31 - (streams - 1) * stride,
                ));
            }
        }
        for t in [0, 1] {
            let last = match (streams, t) {
                (1, 0) => 31,
                (1, 1) | (2, 0) => 30,
                (2, 1) | (3, 0) => 29,
                (3, 1) => 27,
                (4, 0) => 28,
                (4, 1) => 25,
                _ => unreachable!(),
            };
            for size in 0..3 {
                cases.push((
                    0xf4a0_000f | ((streams + 11) << 8) | (size << 6) | (t << 5),
                    last,
                ));
            }
            if streams == 4 {
                // The separately allocated 32-bit, 16-byte-aligned all-lanes form.
                cases.push((0xf4a0_0fdf | (t << 5), last));
            }
        }
    }
    cases
        .into_iter()
        .flat_map(|(base, last)| [2, 13, 15].map(move |rm| ((base & !15) | rm, last)))
        .collect()
}

fn word(base: u32, first: u32, rn: u32, thumb: bool) -> u32 {
    assert!(first < 32 && rn < 16);
    let raw = base | ((first & 16) << 18) | ((first & 15) << 12) | (rn << 16);
    if thumb {
        (raw & 0x00ff_ffff) | 0xf900_0000
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

fn execute(raw: u32, thumb: bool, denial: u8, skipped: bool) -> ExecResult {
    let mut cpu = Armv7Cpu::new();
    cpu.regs[0] = 0x400;
    cpu.regs[2] = 0x20;
    cpu.regs[15] = 0x100;
    cpu.cpsr.t = thumb;
    cpu.cp15.cpacr = Cpacr::from_bits(0x00f0_0000);
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
        cpu.cpsr.it_state = 0x18; // IT NE fails with Z=1.
        cpu.cpsr.z = true;
    }
    cpu.vfp.dregs.fill(0x0123_4567_89ab_cdef);
    let before = (
        cpu.regs,
        cpu.vfp.dregs,
        cpu.vfp.fpscr.bits(),
        cpu.cpsr.to_u32(),
    );
    let mut memory = FlatMemory::new(4096, 0);
    let result = Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb));
    if skipped || !matches!(result, ExecResult::Continue) {
        assert_eq!(
            (
                cpu.regs,
                cpu.vfp.dregs,
                cpu.vfp.fpscr.bits(),
                cpu.cpsr.to_u32()
            ),
            before,
            "raw={raw:08x}, denial={denial}, skipped={skipped}"
        );
        assert!(
            (0..4096)
                .step_by(4)
                .all(|a| memory.read_word(a).unwrap() == 0)
        );
    }
    result
}

#[test]
fn structure_lists_and_pc_bases_reject_during_arm_and_thumb_decode() {
    for (base, last) in forms() {
        for thumb in [false, true] {
            assert_ne!(
                decode(word(base, last, 0, thumb), thumb).mnemonic,
                Mnemonic::UNDEFINED
            );
            for raw in [
                Some(word(base, last, 15, thumb)),
                (last < 31).then(|| word(base, last + 1, 0, thumb)),
            ]
            .into_iter()
            .flatten()
            {
                assert_eq!(
                    decode(raw, thumb).mnemonic,
                    Mnemonic::UNDEFINED,
                    "{raw:08x}"
                );
            }
        }
    }
}

#[test]
fn invalid_structure_operands_precede_all_represented_access_denials() {
    for (base, last) in forms() {
        for thumb in [false, true] {
            for raw in [
                Some(word(base, last, 15, thumb)),
                (last < 31).then(|| word(base, last + 1, 0, thumb)),
            ]
            .into_iter()
            .flatten()
            {
                for denial in 0..=2 {
                    let result = execute(raw, thumb, denial, false);
                    assert!(
                        matches!(result, ExecResult::Undefined),
                        "{raw:08x}, denial={denial}: {result:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn last_valid_structure_registers_execute_or_take_the_selected_fp_trap() {
    for (base, last) in forms() {
        for thumb in [false, true] {
            let raw = word(base, last, 0, thumb);
            for denial in [0, 2] {
                let result = execute(raw, thumb, denial, false);
                assert!(
                    match denial {
                        0 => matches!(result, ExecResult::Continue),
                        _ => matches!(result, ExecResult::FpAccessTrap { target_el: 2, .. }),
                    },
                    "{raw:08x}, denial={denial}: {result:?}"
                );
            }
        }
    }
}

#[test]
fn failed_thumb_it_suppresses_invalid_structure_operands_and_access_checks() {
    for (base, last) in forms() {
        for raw in [
            Some(word(base, last, 15, true)),
            (last < 31).then(|| word(base, last + 1, 0, true)),
        ]
        .into_iter()
        .flatten()
        {
            assert!(matches!(execute(raw, true, 2, true), ExecResult::Continue));
        }
    }
}

#[test]
fn mixed_width_structure_operand_failures_do_not_retire_or_raise_fp_syndromes() {
    for (base, last) in forms() {
        for thumb in [false, true] {
            for raw in [
                Some(word(base, last, 15, thumb)),
                (last < 31).then(|| word(base, last + 1, 0, thumb)),
            ]
            .into_iter()
            .flatten()
            {
                let mut cpu = super::mixed(raw, thumb, 2, false, true);
                let vector = cpu.get_simd(0);
                let result = cpu.step();
                assert!(
                    matches!(result, Err(ArmError::UndefinedInstruction(value)) if value == raw),
                    "{raw:08x}: {result:?}"
                );
                assert_eq!(cpu.get_pc(), 0x100);
                assert_eq!(cpu.instruction_count(), 0);
                assert_eq!(cpu.get_simd(0), vector);
            }
        }
    }
}

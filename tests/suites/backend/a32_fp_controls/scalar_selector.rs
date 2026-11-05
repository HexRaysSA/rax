//! Arm DDI0597 ID032025 scalar VMLA/VMLS/VMUL and widening-selector boundaries.
use rax::isa::arm::aarch32::{cp15::Cpacr, cpu::ProcessorMode};
use rax::isa::arm::common::cpu::{ArmCpu, ArmError};
use rax::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, Mnemonic, ThumbDecoder};
use rax::isa::arm::execution::{ArmMemory, FlatMemory};
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};

fn decode(raw: u32, thumb: bool) -> DecodedInsn {
    if thumb {
        ThumbDecoder::decode_32bit(raw).unwrap()
    } else {
        Aarch32Decoder::decode(raw).unwrap()
    }
}

fn word(raw: u32, thumb: bool) -> u32 {
    if thumb {
        (raw & 0x00ff_ffff) | 0xef00_0000 | (((raw >> 24) & 1) << 28)
    } else {
        raw
    }
}

#[test]
fn scalar_register_fields_reject_reserved_sizes_before_widening_dispatch() {
    for thumb in [false, true] {
        for q in 0..2 {
            // size=3 selects related encodings and is deliberately excluded.
            for size in 0..3 {
                for d in 0..32 {
                    for n in 0..32 {
                        for m in 0..32 {
                            for (opcode, mnemonic) in [
                                (1, Mnemonic::VMLA),
                                (5, Mnemonic::VMLS),
                                (9, Mnemonic::VMUL),
                            ] {
                                let raw = word(
                                    0xf280_0040
                                        | (q << 24)
                                        | (size << 20)
                                        | ((d >> 4) << 22)
                                        | ((d & 15) << 12)
                                        | ((n >> 4) << 7)
                                        | ((n & 15) << 16)
                                        | ((m >> 4) << 5)
                                        | (m & 15)
                                        | (opcode << 8),
                                    thumb,
                                );
                                let valid = size != 0 && !(q == 1 && (d | n) & 1 != 0);
                                assert_eq!(
                                    decode(raw, thumb).mnemonic,
                                    if valid { mnemonic } else { Mnemonic::UNDEFINED },
                                    "raw={raw:08x}, thumb={thumb}"
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
fn scalar_size_three_fallback_preserves_all_vext_neighbors() {
    let mut cases = 0;
    for thumb in [false, true] {
        for q in 0..2 {
            for immediate in 0..16 {
                for d in 0..32 {
                    for n in 0..32 {
                        for m in 0..32 {
                            let raw = word(
                                0xf2b0_0000
                                    | ((d >> 4) << 22)
                                    | ((d & 15) << 12)
                                    | ((n >> 4) << 7)
                                    | ((n & 15) << 16)
                                    | ((m >> 4) << 5)
                                    | (m & 15)
                                    | (q << 6)
                                    | (immediate << 8),
                                thumb,
                            );
                            // DDI0597 VEXT: a D-register result admits only
                            // immediates 0..7; Q operands require even D indices.
                            let allocated = if q == 0 {
                                immediate < 8
                            } else {
                                (d | n | m) & 1 == 0
                            };
                            assert_eq!(
                                decode(raw, thumb).mnemonic,
                                if allocated {
                                    Mnemonic::VEXT
                                } else {
                                    Mnemonic::UNDEFINED
                                },
                                "raw={raw:08x}, thumb={thumb}"
                            );
                            cases += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 2_097_152);
}

const RESERVED: [u32; 6] = [
    0xf280_0140,
    0xf380_0140,
    0xf280_0540,
    0xf380_0540,
    0xf280_0940,
    0xf380_0940,
];

fn execute(raw: u32, thumb: bool, denial: u8, skipped: bool) -> ExecResult {
    let mut cpu = Armv7Cpu::new();
    cpu.regs[15] = 0x800;
    cpu.cpsr.t = thumb;
    cpu.cp15.cpacr = Cpacr::from_bits(0x00f0_0000);
    for (id, register) in cpu.vfp.dregs.iter_mut().enumerate() {
        *register = 0x0706_0504_0302_0100 ^ (id as u64 * 0x0101_0101_0101_0101);
    }
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
            cpu.cpsr.to_u32()
        ),
        before,
        "raw={raw:08x}, thumb={thumb}, denial={denial}, skipped={skipped}"
    );
    let memory_unchanged = (0..4096)
        .step_by(4)
        .all(|a| memory.read_word(a).unwrap() == 0);
    assert!(memory_unchanged);
    result
}

#[test]
fn reserved_scalar_forms_precede_access_denials_without_effects() {
    for raw in RESERVED {
        for thumb in [false, true] {
            for denial in 0..3 {
                let raw = word(raw, thumb);
                assert!(
                    matches!(execute(raw, thumb, denial, false), ExecResult::Undefined),
                    "raw={raw:08x}, thumb={thumb}, denial={denial}"
                );
            }
        }
    }
}

#[test]
fn failed_thumb_it_suppresses_reserved_scalar_operand_faults() {
    for raw in RESERVED {
        for denial in 0..3 {
            assert!(matches!(
                execute(word(raw, true), true, denial, true),
                ExecResult::Continue
            ));
        }
    }
}

#[test]
fn mixed_width_reserved_scalar_forms_do_not_become_higher_el_fp_traps() {
    for raw in RESERVED {
        for thumb in [false, true] {
            let raw = word(raw, thumb);
            let mut cpu = super::mixed(raw, thumb, 2, false, true);
            let registers = cpu.export_sregs();
            let vector: Vec<_> = (0..32).map(|id| cpu.get_simd(id)).collect();
            assert!(
                matches!(cpu.step(), Err(ArmError::UndefinedInstruction(value)) if value == raw),
                "raw={raw:08x}, thumb={thumb}"
            );
            assert_eq!(cpu.export_sregs(), registers);
            assert_eq!(
                (0..32).map(|id| cpu.get_simd(id)).collect::<Vec<_>>(),
                vector
            );
            assert_eq!(cpu.get_pc(), 0x100);
            assert_eq!(cpu.instruction_count(), 0);
        }
    }
}

#[test]
fn scalar_and_widening_positive_neighbors_preserve_their_defined_data_paths() {
    for thumb in [false, true] {
        // size=3 belongs to related encodings; this one remains VEXT.
        assert_eq!(
            decode(word(0xf2b4_0142, thumb), thumb).mnemonic,
            Mnemonic::VEXT
        );
        for q in 0..2 {
            for (opcode, mnemonic, expected) in [
                (1, Mnemonic::VMLA, 0x40e0_0000u64),
                (5, Mnemonic::VMLS, 0xc0a0_0000),
                (9, Mnemonic::VMUL, 0x40c0_0000),
            ] {
                let mut cpu = Armv7Cpu::new();
                cpu.cpsr.t = thumb;
                cpu.cp15.cpacr = Cpacr::from_bits(0x00f0_0000);
                cpu.vfp.dregs.fill(0x3f80_0000_3f80_0000);
                cpu.vfp.dregs[2] = 0x4040_0000_4040_0000;
                cpu.vfp.dregs[4] = 0x4000_0000_4000_0000;
                cpu.vfp.dregs[5] = 0x4000_0000_4000_0000;
                let before = cpu.vfp.dregs;
                let raw = word(0xf2a4_0042 | (q << 24) | (opcode << 8), thumb);
                let insn = decode(raw, thumb);
                assert_eq!(insn.mnemonic, mnemonic);
                let mut memory = FlatMemory::new(4096, 0);
                assert!(matches!(
                    Executor::new(&mut cpu, &mut memory).execute(&insn),
                    ExecResult::Continue
                ));
                let mut expected_regs = before;
                expected_regs[0] = expected | expected << 32;
                if q != 0 {
                    expected_regs[1] = expected_regs[0];
                }
                assert_eq!(cpu.vfp.dregs, expected_regs, "raw={raw:08x}, thumb={thumb}");
                assert_eq!(cpu.vfp.fpscr.bits(), 0);
            }
            let mut cpu = Armv7Cpu::new();
            cpu.cpsr.t = thumb;
            cpu.cp15.cpacr = Cpacr::from_bits(0x00f0_0000);
            cpu.vfp.dregs[2] = 0x0303_0303_0303_0303;
            cpu.vfp.dregs[4] = 0x0002_0002_0002_0002;
            cpu.vfp.dregs[5] = 0x0002_0002_0002_0002;
            let before = cpu.vfp.dregs;
            let raw = word(0xf284_0102 | (q << 24), thumb);
            let insn = decode(raw, thumb);
            assert_eq!(insn.mnemonic, Mnemonic::VADDW);
            let mut memory = FlatMemory::new(4096, 0);
            assert!(matches!(
                Executor::new(&mut cpu, &mut memory).execute(&insn),
                ExecResult::Continue
            ));
            let mut expected = before;
            expected[0] = 0x0005_0005_0005_0005;
            expected[1] = expected[0];
            assert_eq!(cpu.vfp.dregs, expected);
        }
    }
}

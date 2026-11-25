//! Unconditional coprocessor routing and ordinary FP transfer prefixes.
use rax::isa::arm::aarch32::{cp15::Cpacr, cpu::ProcessorMode, vfp::Fpscr};
use rax::isa::arm::aarch64::AArch64Config;
use rax::isa::arm::common::cpu::{ArmCpu, ArmError};
use rax::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, Mnemonic, ThumbDecoder};
use rax::isa::arm::execution::FlatMemory;
use rax::isa::arm::{Armv7Cpu, ExceptionType, ExecResult, Executor};
use rax::smir::ir::types::SourceArch;
use rax::smir::lift::aarch32::Aarch32Lifter;
use rax::smir::lift::thumb::ThumbLifter;
use rax::smir::lift::{LiftContext, LiftError, SmirLifter};

const INVALID: &[u32] = &[
    0xfc41_0b10,
    0xfc51_0b10,
    0xfe00_0a10,
    0xfe10_0a10,
    0xfef1_0a10,
    0xfee1_0a10,
    0xfee0_0b10,
    0xfd90_0b00,
    0xfd80_0b00,
];

fn decode(raw: u32, thumb: bool) -> DecodedInsn {
    if thumb {
        ThumbDecoder::decode_32bit(raw)
    } else {
        Aarch32Decoder::decode(raw)
    }
    .unwrap()
}

#[test]
fn reserved_unconditional_fp_transfer_register_fields_are_undefined() {
    for &base in INVALID {
        for thumb in [false, true] {
            for first in 0..16 {
                for second in 0..16 {
                    for low in 0..16 {
                        let raw = (base & !0x000f_f00f) | first << 12 | second << 16 | low;
                        assert_eq!(
                            decode(raw, thumb).mnemonic,
                            Mnemonic::UNDEFINED,
                            "raw={raw:08x}, thumb={thumb}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn conditional_cp10_transfer_opcodes_do_not_resolve_to_system_operations() {
    for thumb in [false, true] {
        for opcode in 1..=6 {
            for read in [0, 1] {
                for extension in 0..16 {
                    for core in 0..16 {
                        let raw =
                            0xee00_0a10 | opcode << 21 | read << 20 | extension << 16 | core << 12;
                        assert_eq!(
                            decode(raw, thumb).mnemonic,
                            Mnemonic::UNDEFINED,
                            "raw={raw:08x}, thumb={thumb}"
                        );
                    }
                }

                let raw = 0xee01_0a10 | opcode << 21 | read << 20;
                let mut cpu = super::mixed(raw, thumb, 2, false, true);
                let registers = (cpu.get_gpr(0), cpu.get_simd(0), cpu.export_sregs());
                assert!(
                    matches!(cpu.step(), Err(ArmError::UndefinedInstruction(value)) if value == raw),
                    "raw={raw:08x}, thumb={thumb}"
                );
                assert_eq!(cpu.get_pc(), 0x100);
                assert_eq!(cpu.instruction_count(), 0);
                assert_eq!(
                    (cpu.get_gpr(0), cpu.get_simd(0), cpu.export_sregs()),
                    registers
                );
            }
        }
        for (raw, mnemonic) in [
            (0xee01_0a10, Mnemonic::VMOV),
            (0xee11_0a10, Mnemonic::VMOV),
            (0xeee1_0a10, Mnemonic::VMSR),
            (0xeef1_0a10, Mnemonic::VMRS),
        ] {
            assert_eq!(
                decode(raw, thumb).mnemonic,
                mnemonic,
                "{raw:08x}, thumb={thumb}"
            );
        }
    }
}

#[test]
fn vmrs_vmsr_reserved_fields_fail_decode() {
    for thumb in [false, true] {
        for (base, registers, canonical) in [
            (0xeef0_0a10, &[0, 1, 5, 6, 7, 8][..], Mnemonic::VMRS),
            (0xeee0_0a10, &[0, 1, 8][..], Mnemonic::VMSR),
        ] {
            for &register in registers {
                for core in 0..15 {
                    let word = base | register << 16 | core << 12;
                    assert_eq!(decode(word, thumb).mnemonic, canonical);
                    for field in 1..128 {
                        // [7:5] and [3:0] are SBZ. Bit 4 remains the transfer selector.
                        let raw = word | ((field & 0x70) << 1) | (field & 0xf);
                        assert_eq!(
                            decode(raw, thumb).mnemonic,
                            Mnemonic::UNDEFINED,
                            "raw={raw:08x}, thumb={thumb}"
                        );
                    }
                }
            }
        }
        assert_eq!(decode(0xeef1_fa10, thumb).mnemonic, Mnemonic::VMRS);
    }
}

#[test]
fn vmrs_vmsr_reserved_fields_precede_fp_access_and_preserve_predication() {
    for thumb in [false, true] {
        for word in [0xeef1_2a10, 0xeee1_2a10, 0xeef1_fa10, 0xeee8_2a10] {
            for skip in [false, true] {
                let mut raw = word | 0xef;
                let mut cpu = Armv7Cpu::new();
                cpu.cpsr.t = thumb;
                if skip && thumb {
                    cpu.cpsr.it_state = 0x18; // IT NE, with Z=1 below.
                } else if skip {
                    raw ^= 0xf000_0000; // NE, with Z=1 below.
                }
                cpu.cpsr.z = true;
                cpu.regs[2] = 0x00c0_0000;
                cpu.vfp.fpscr = Fpscr::from_bits(0xa000_0001);
                let before = (
                    cpu.regs,
                    cpu.vfp.fpscr.bits(),
                    cpu.vfp.fpexc,
                    cpu.cpsr.to_u32(),
                );
                let mut memory = FlatMemory::new(32, 0);
                let result = Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb));
                assert!(
                    matches!(result, ExecResult::Continue) && skip
                        || matches!(result, ExecResult::Undefined) && !skip,
                    "raw={raw:08x}, thumb={thumb}, skip={skip}: {result:?}"
                );
                assert_eq!(
                    (
                        cpu.regs,
                        cpu.vfp.fpscr.bits(),
                        cpu.vfp.fpexc,
                        cpu.cpsr.to_u32()
                    ),
                    before
                );
            }

            let raw = word | 0x80;
            let mut cpu = super::mixed(raw, thumb, 2, false, true);
            let before = (cpu.get_gpr(2), cpu.export_sregs());
            assert!(
                matches!(cpu.step(), Err(ArmError::UndefinedInstruction(value)) if value == raw),
                "raw={raw:08x}, thumb={thumb}"
            );
            assert_eq!((cpu.get_gpr(2), cpu.export_sregs()), before);
            assert_eq!(cpu.get_pc(), 0x100);
            assert_eq!(cpu.instruction_count(), 0);

            let mut cpu = super::mixed(word, thumb, 2, false, true);
            assert!(matches!(
                cpu.step(),
                Err(ArmError::ArchitecturalException {
                    ec: 7,
                    target_el: Some(2),
                    ..
                })
            ));
        }
    }
}

#[test]
fn invalid_single_vmov_fields_cannot_take_a_higher_level_fp_trap() {
    for thumb in [false, true] {
        for word in [0xee01_0990, 0xee11_0990, 0xee01_0a90, 0xee11_0a90] {
            let raw = word | 0x6f;
            let mut cpu =
                super::mixed_with_config(raw, thumb, 2, false, true, AArch64Config::v8_2());
            let registers = (cpu.get_gpr(0), cpu.get_simd(0), cpu.export_sregs());
            assert!(
                matches!(cpu.step(), Err(ArmError::UndefinedInstruction(value)) if value == raw),
                "raw={raw:08x}, thumb={thumb}"
            );
            assert_eq!(cpu.get_pc(), 0x100);
            assert_eq!(cpu.instruction_count(), 0);
            assert_eq!(
                (cpu.get_gpr(0), cpu.get_simd(0), cpu.export_sregs()),
                registers
            );

            let mut cpu =
                super::mixed_with_config(word, thumb, 2, false, true, AArch64Config::v8_2());
            let result = cpu.step();
            assert!(
                matches!(
                    result,
                    Err(ArmError::ArchitecturalException {
                        ec: 7,
                        target_el: Some(2),
                        ..
                    })
                ),
                "raw={word:08x}, thumb={thumb}: {result:?}"
            );
        }
    }
}

#[test]
fn cp11_lane_and_duplicate_transfers_check_reserved_low_nibble() {
    for thumb in [false, true] {
        for (word, mnemonic) in [
            (0xee40_0b10, Mnemonic::VMOV), // Core to byte.
            (0xee00_0b30, Mnemonic::VMOV), // Core to halfword.
            (0xee00_0b10, Mnemonic::VMOV), // Core to word.
            (0xee50_0b10, Mnemonic::VMOV), // Signed byte to core.
            (0xeed0_0b10, Mnemonic::VMOV), // Unsigned byte to core.
            (0xee10_0b30, Mnemonic::VMOV), // Signed halfword to core.
            (0xee90_0b30, Mnemonic::VMOV), // Unsigned halfword to core.
            (0xee10_0b10, Mnemonic::VMOV), // Word to core.
            (0xeec0_0b10, Mnemonic::VDUP),
            (0xee80_0b30, Mnemonic::VDUP),
            (0xee80_0b10, Mnemonic::VDUP),
            (0xeea0_0b30, Mnemonic::VDUP), // Q destination.
        ] {
            let quad = mnemonic == Mnemonic::VDUP && word & (1 << 21) != 0;
            for d in 0..32 {
                for t in 0..16 {
                    let base = word | ((d & 15) << 16) | ((d >> 4) << 7) | (t << 12);
                    for low in 0..16 {
                        let raw = base | low;
                        let expected = if low != 0 || t == 15 || quad && d & 1 != 0 {
                            Mnemonic::UNDEFINED
                        } else {
                            mnemonic
                        };
                        assert_eq!(decode(raw, thumb).mnemonic, expected, "{raw:08x}, {thumb}");
                    }
                }
            }
        }
    }
}

#[test]
fn cp11_reserved_low_nibble_precedes_fp_access_and_respects_predicates() {
    const CORE: u32 = 0x8122_33d5;
    const VECTOR: u64 = 0x89ab_cdef_7654_fedc;
    for thumb in [false, true] {
        for (word, core_after, vector_after) in [
            (0xee40_2b10, CORE, 0x89ab_cdef_7654_fed5),
            (0xee50_2b10, 0xffff_ffdc, VECTOR),
            (0xee80_2b30, CORE, 0x33d5_33d5_33d5_33d5),
        ] {
            for low in [0, 1, 15] {
                for skip in [false, true] {
                    let mut raw = word | low;
                    let mut cpu = Armv7Cpu::new();
                    cpu.cpsr.t = thumb;
                    cpu.cpsr.z = true;
                    if skip && thumb {
                        cpu.cpsr.it_state = 0x18; // IT NE, Z=1.
                    } else if skip {
                        raw ^= 0xf000_0000; // NE, Z=1.
                    }
                    cpu.cp15.cpacr = Cpacr::from_bits(0x00f0_0000);
                    cpu.vfp.fpexc = 1 << 30;
                    cpu.regs[2] = CORE;
                    cpu.vfp.dregs.fill(VECTOR);
                    let mut regs = cpu.regs;
                    let mut vectors = cpu.vfp.dregs;
                    let fpscr = cpu.vfp.fpscr.bits();
                    let mut memory = FlatMemory::new(32, 0);
                    let result = Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb));
                    if low == 0 && !skip {
                        regs[2] = core_after;
                        vectors[0] = vector_after;
                    }
                    assert!(
                        matches!(result, ExecResult::Continue) && (low == 0 || skip)
                            || matches!(result, ExecResult::Undefined) && low != 0 && !skip,
                        "raw={raw:08x}, thumb={thumb}, skipped={skip}: {result:?}"
                    );
                    assert_eq!(
                        (cpu.regs, cpu.vfp.dregs, cpu.vfp.fpscr.bits()),
                        (regs, vectors, fpscr)
                    );
                }
            }

            let raw = word | 1;
            let mut cpu = super::mixed(raw, thumb, 2, false, true);
            let before = (cpu.get_gpr(2), cpu.get_simd(0), cpu.export_sregs());
            assert!(
                matches!(cpu.step(), Err(ArmError::UndefinedInstruction(value)) if value == raw),
                "raw={raw:08x}, thumb={thumb}"
            );
            assert_eq!(
                (cpu.get_gpr(2), cpu.get_simd(0), cpu.export_sregs()),
                before
            );
            assert_eq!(cpu.get_pc(), 0x100);
            assert_eq!(cpu.instruction_count(), 0);
            let mut cpu = super::mixed(word, thumb, 2, false, true);
            let result = cpu.step();
            assert!(
                matches!(
                    result,
                    Err(ArmError::ArchitecturalException {
                        ec: 7,
                        target_el: Some(2),
                        ..
                    })
                ),
                "raw={word:08x}, thumb={thumb}: {result:?}"
            );
        }
    }
}

#[test]
fn generic_unconditional_families_and_conditional_svc_keep_their_allocation() {
    for thumb in [false, true] {
        for coprocessor in (0..8).chain(12..16) {
            for (base, expected) in [
                (0xfc41_0010, Mnemonic::MCRR),
                (0xfc51_0010, Mnemonic::MRRC),
                (0xfd90_0000, Mnemonic::LDC),
                (0xfd80_0000, Mnemonic::STC),
                // opc1=0 shares the p13 encoding with VDOT.BF16.
                (0xfe12_0044, Mnemonic::CDP2),
                (0xfe00_0010, Mnemonic::MCR2),
                (0xfe10_0010, Mnemonic::MRC2),
            ] {
                let raw = base | coprocessor << 8;
                assert_eq!(
                    decode(raw, thumb).mnemonic,
                    expected,
                    "raw={raw:08x}, thumb={thumb}"
                );
            }
            for raw in [0xfc00_0000, 0xfc10_0000] {
                let raw = raw | coprocessor << 8;
                let expected = if raw == 0xfc00_0d00 {
                    Mnemonic::VDOT_BF16 // The p13 allocation precedes generic coprocessor decode.
                } else {
                    Mnemonic::UNDEFINED
                };
                assert_eq!(
                    decode(raw, thumb).mnemonic,
                    expected,
                    "raw={raw:08x}, thumb={thumb}"
                );
            }
        }
    }
    for condition in 0..15 {
        let raw = condition << 28 | 0x0f00_0017;
        assert_eq!(decode(raw, false).mnemonic, Mnemonic::SVC, "{raw:08x}");
    }
    assert_eq!(decode(0xff00_0017, false).mnemonic, Mnemonic::UNDEFINED);
    assert_eq!(
        ThumbDecoder::decode_16bit(0xdf17).unwrap().mnemonic,
        Mnemonic::SVC
    );
}

#[test]
fn invalid_transfer_prefixes_precede_access_denials_without_effects() {
    for &raw in INVALID {
        for thumb in [false, true] {
            for denial in 0..4 {
                let mut cpu = Armv7Cpu::new();
                cpu.cpsr.t = thumb;
                cpu.cp15.cpacr = Cpacr::from_bits(if denial == 1 { 0 } else { 0x00f0_0000 });
                cpu.vfp.fpexc = if denial == 3 { 0 } else { 1 << 30 };
                if denial == 2 {
                    cpu.cpsr.mode = ProcessorMode::Hyp as u8;
                    cpu.cp15.scr = 1;
                    cpu.cp15.nsacr = 1 << 10;
                    cpu.cp15.hcptr = 1 << 10;
                }
                cpu.regs.fill(0x1020_3040);
                cpu.vfp.dregs.fill(0x3ff0_0000_3f80_0000);
                cpu.vfp.fpscr = Fpscr::from_bits(0xa800_009f);
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
                    matches!(
                        result,
                        ExecResult::Undefined
                            | ExecResult::Exception(ExceptionType::UndefinedInstruction)
                    ),
                    "raw={raw:08x}, thumb={thumb}, denial={denial}: {result:?}"
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
            let bytes = if thumb {
                [
                    ((raw >> 16) as u16).to_le_bytes(),
                    (raw as u16).to_le_bytes(),
                ]
                .concat()
            } else {
                raw.to_le_bytes().to_vec()
            };
            let lifted = if thumb {
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
                matches!(lifted, Err(LiftError::Unsupported { addr: 0x100, .. })),
                "raw={raw:08x}, thumb={thumb}: {lifted:?}"
            );
        }
    }
}

#[test]
fn mixed_width_invalid_transfers_do_not_select_fp_or_svc_or_retire() {
    for &raw in INVALID {
        for thumb in [false, true] {
            let mut cpu = super::mixed(raw, thumb, 2, false, true);
            let system = cpu.export_sregs();
            let gprs: Vec<_> = (0..31).map(|reg| cpu.get_gpr(reg)).collect();
            let vectors: Vec<_> = (0..32).map(|reg| cpu.get_simd(reg)).collect();
            assert!(
                matches!(cpu.step(), Err(ArmError::UndefinedInstruction(value)) if value == raw),
                "raw={raw:08x}, thumb={thumb}"
            );
            assert_eq!(cpu.export_sregs(), system);
            assert_eq!(
                (0..31).map(|reg| cpu.get_gpr(reg)).collect::<Vec<_>>(),
                gprs
            );
            assert_eq!(
                (0..32).map(|reg| cpu.get_simd(reg)).collect::<Vec<_>>(),
                vectors
            );
            assert_eq!(cpu.get_pc(), 0x100);
            assert_eq!(cpu.instruction_count(), 0);
        }
    }
}

#[test]
fn reserved_cp10_cp11_pair_and_memory_encodings_are_undefined() {
    const RESERVED: &[u32] = &[
        0xec40_0a00, // Pair, D=1 but o3=0.
        0xec00_0a10, // Pair, D=0.
        0xec40_0a50, // Pair, opc2=01.
        0xec40_0a90, // Pair, opc2=10.
        0xec40_0ad0, // Pair, opc2=11.
        0xec20_0a00, // Memory, P=0 U=0 W=1.
        0xeda0_0a00, // Memory, P=1 U=1 W=1.
    ];
    for thumb in [false, true] {
        for &template in RESERVED {
            for coproc_low in [0, 1] {
                for read in [0, 1] {
                    let base = template | coproc_low << 8 | read << 20;
                    for first in 0..16 {
                        for second in 0..16 {
                            let raw = base | first << 12 | second << 16;
                            assert_eq!(
                                decode(raw, thumb).mnemonic,
                                Mnemonic::UNDEFINED,
                                "raw={raw:08x}, thumb={thumb}"
                            );
                        }
                    }
                    let raw = base | 1 << 16;
                    let mut cpu = super::mixed(raw, thumb, 2, false, true);
                    let before = (cpu.get_gpr(0), cpu.get_simd(0), cpu.export_sregs());
                    assert!(
                        matches!(cpu.step(), Err(ArmError::UndefinedInstruction(value)) if value == raw),
                        "raw={raw:08x}, thumb={thumb}"
                    );
                    assert_eq!(cpu.get_pc(), 0x100);
                    assert_eq!(cpu.instruction_count(), 0);
                    assert_eq!(
                        (cpu.get_gpr(0), cpu.get_simd(0), cpu.export_sregs()),
                        before
                    );
                }
            }
        }
        for (raw, mnemonic) in [
            (0xec41_0a10, Mnemonic::VMOV),
            (0xec51_0b10, Mnemonic::VMOV),
            (0xed90_0a04, Mnemonic::VLDR),
            (0xed80_0b04, Mnemonic::VSTR),
            (0xec41_0f10, Mnemonic::MCRR),
            (0xec51_0f10, Mnemonic::MRRC),
        ] {
            assert_eq!(
                decode(raw, thumb).mnemonic,
                mnemonic,
                "raw={raw:08x}, thumb={thumb}"
            );
        }
    }
}

#[test]
fn reserved_cp8_cp9_pair_and_memory_encodings_are_undefined() {
    for thumb in [false, true] {
        for prefix in if thumb { 14..=14 } else { 0..=14 } {
            for coproc in [8, 9] {
                for puw in 0..8 {
                    // Size 01 is allocated only for conditional immediate VLDR/VSTR.
                    if coproc == 9 && matches!(puw, 0b100 | 0b110) {
                        continue;
                    }
                    for d in 0..2 {
                        for load in 0..2 {
                            for imm in [0x00, 0x01, 0x10, 0x53, 0xff] {
                                let raw = (prefix << 28)
                                    | 0x0c01_0000
                                    | ((puw & 0b110) << 22)
                                    | (d << 22)
                                    | ((puw & 1) << 21)
                                    | (load << 20)
                                    | (coproc << 8)
                                    | imm;
                                assert_eq!(
                                    decode(raw, thumb).mnemonic,
                                    Mnemonic::UNDEFINED,
                                    "raw={raw:08x}, thumb={thumb}"
                                );
                            }
                        }
                    }
                }
            }
        }

        for (raw, mnemonic) in [
            (0xed01_0903, Mnemonic::VSTR),
            (0xed81_0903, Mnemonic::VSTR),
            (0xed11_0903, Mnemonic::VLDR),
            (0xed91_0903, Mnemonic::VLDR),
            (0xec41_0a10, Mnemonic::VMOV),
            (0xec51_0f10, Mnemonic::MRRC),
            (0xed91_0703, Mnemonic::LDC),
            (0xfc21_0800, Mnemonic::VCMLA),
            (0xfd91_0800, Mnemonic::VCADD),
        ] {
            assert_eq!(
                decode(raw, thumb).mnemonic,
                mnemonic,
                "raw={raw:08x}, thumb={thumb}"
            );
        }
    }
}

#[test]
fn reserved_cp8_cp9_memory_prefixes_do_not_retire_or_trap_to_el2() {
    for thumb in [false, true] {
        for raw in [0xec41_0810, 0xec51_0910, 0xed81_0804, 0xec91_0901] {
            let mut cpu = super::mixed(raw, thumb, 2, false, true);
            let before = (cpu.get_gpr(1), cpu.get_simd(0), cpu.export_sregs());
            assert!(
                matches!(cpu.step(), Err(ArmError::UndefinedInstruction(value)) if value == raw),
                "raw={raw:08x}, thumb={thumb}"
            );
            assert_eq!(cpu.get_pc(), 0x100);
            assert_eq!(cpu.instruction_count(), 0);
            assert_eq!(
                (cpu.get_gpr(1), cpu.get_simd(0), cpu.export_sregs()),
                before
            );
        }
    }
}

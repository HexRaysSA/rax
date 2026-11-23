//! Unconditional coprocessor routing and ordinary FP transfer prefixes.
use rax::isa::arm::aarch32::{cp15::Cpacr, cpu::ProcessorMode, vfp::Fpscr};
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

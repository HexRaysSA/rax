//! Primary scalar-FP prefix allocation and generic coprocessor boundaries.
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
    0xee02_0d44,
    0xee02_0e44,
    0xee81_0e02,
    0xfeb1_0b42,
    0xfeb1_0bc1,
    0xfeb0_0bc1,
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
fn scalar_data_coprocessor_fields_do_not_alias_other_coprocessors() {
    for thumb in [false, true] {
        for condition in 0..15 {
            if thumb && condition != 14 {
                continue;
            }
            for (base, expected) in [
                (0xee02_0a44, Mnemonic::VMLS),
                (0xee81_0a02, Mnemonic::VDIV),
                (0xee31_0a02, Mnemonic::VADD),
            ] {
                for coprocessor in 0..16 {
                    let raw = (base & !0xf000_0f00) | (condition << 28) | (coprocessor << 8);
                    let actual = decode(raw, thumb).mnemonic;
                    match coprocessor {
                        8 => assert_eq!(actual, Mnemonic::UNDEFINED, "{raw:08x}"),
                        9..=11 => assert_eq!(actual, expected, "{raw:08x}"),
                        _ => assert!(
                            matches!(actual, Mnemonic::CDP | Mnemonic::CDP2),
                            "raw={raw:08x}, thumb={thumb}: {actual:?}"
                        ),
                    }
                }
            }
        }
    }
}

#[test]
fn unconditional_scalar_unary_prefixes_do_not_allocate_fp() {
    for thumb in [false, true] {
        for base in [0xfeb1_0b42, 0xfeb1_0bc1, 0xfeb0_0bc1] {
            for d in 0..32 {
                for m in 0..32 {
                    let raw = (base & !0x0040_f02f)
                        | ((d & 15) << 12)
                        | ((d >> 4) << 22)
                        | (m & 15)
                        | ((m >> 4) << 5);
                    assert_eq!(
                        decode(raw, thumb).mnemonic,
                        Mnemonic::UNDEFINED,
                        "{raw:08x}"
                    );
                }
            }
        }
    }
}

#[test]
fn invalid_prefixes_reject_before_fp_access_and_preserve_state() {
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
                "raw={raw:08x}, thumb={thumb}: {result:?}"
            );
        }
    }
}

#[test]
fn unconditional_extensions_keep_their_existing_allocations() {
    for thumb in [false, true] {
        for (base, expected) in [
            (0xfe00_0a81, Mnemonic::VSELEQ),
            (0xfe80_0a81, Mnemonic::VMAXNM_F32),
            (0xfebc_0ae0, Mnemonic::VCVTA_S32_F32),
            (0xfeb8_0a60, Mnemonic::VRINTA_F32),
            (0xfeb0_0a40, Mnemonic::VMOVX_F16),
            (0xfeb0_0ac0, Mnemonic::VINS_F16),
        ] {
            for d in 0..32 {
                for m in 0..32 {
                    let raw = (base & !0x0040_f02f)
                        | ((d & 15) << 12)
                        | ((d >> 4) << 22)
                        | (m & 15)
                        | ((m >> 4) << 5);
                    assert_eq!(decode(raw, thumb).mnemonic, expected, "{raw:08x}");
                }
            }
        }
    }
}

#[test]
fn half_core_dont_care_fields_retain_the_primary_allocation() {
    // Arm ASL VMOV_h marks these six bits x, not fixed zero. LLVM's
    // narrower disassembler acceptance is not a reason to change this policy.
    for thumb in [false, true] {
        for read in 0..2 {
            for t in 0..16 {
                for n in 0..32 {
                    for ignored in 0..64 {
                        let raw = 0xee00_0910
                            | (read << 20)
                            | (t << 12)
                            | ((n >> 1) << 16)
                            | ((n & 1) << 7)
                            | (ignored & 15)
                            | ((ignored >> 4) << 5);
                        assert_eq!(
                            decode(raw, thumb).mnemonic,
                            if t == 15 {
                                Mnemonic::UNDEFINED
                            } else {
                                Mnemonic::VMOV_F16_CORE
                            },
                            "raw={raw:08x}, thumb={thumb}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn mixed_width_invalid_prefixes_do_not_select_fp_traps_or_retire() {
    for &raw in INVALID {
        for thumb in [false, true] {
            let mut cpu = super::mixed(raw, thumb, 2, false, true);
            let system = cpu.export_sregs();
            let vectors: Vec<_> = (0..32).map(|reg| cpu.get_simd(reg)).collect();
            let gprs: Vec<_> = (0..31).map(|reg| cpu.get_gpr(reg)).collect();
            assert!(
                matches!(cpu.step(), Err(ArmError::UndefinedInstruction(value)) if value == raw),
                "raw={raw:08x}, thumb={thumb}"
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

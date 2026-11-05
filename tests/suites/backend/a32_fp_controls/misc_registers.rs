//! Canonical register forms from Arm DDI0597 ID032025, VMVN/VTRN/VUZP/VZIP.
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
    if thumb { raw | 0x0c00_0000 } else { raw }
}

#[test]
fn misc_register_fields_obey_primary_size_and_alignment_constraints() {
    for thumb in [false, true] {
        for d in 0..2 {
            for size in 0..4 {
                for vd in 0..16 {
                    for q in 0..2 {
                        for m in 0..2 {
                            for vm in 0..16 {
                                for (base, mnemonic) in [
                                    (0xf3b0_0580, Mnemonic::VMVN),
                                    (0xf3b2_0080, Mnemonic::VTRN),
                                    (0xf3b2_0100, Mnemonic::VUZP),
                                    (0xf3b2_0180, Mnemonic::VZIP),
                                ] {
                                    let raw = word(base, thumb)
                                        | (d << 22)
                                        | (size << 18)
                                        | (vd << 12)
                                        | (q << 6)
                                        | (m << 5)
                                        | vm;
                                    // Manufacturer decode constraints, before
                                    // CheckAdvSIMDEnabled in the operation.
                                    let size_valid = match mnemonic {
                                        Mnemonic::VMVN => size == 0,
                                        Mnemonic::VTRN => size != 3,
                                        _ => size != 3 && !(q == 0 && size == 2),
                                    };
                                    let valid = size_valid && !(q == 1 && (vd | vm) & 1 != 0);
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
}

const RESERVED: [u32; 5] = [
    0xf3b4_0582,
    0xf3b8_0582,
    0xf3bc_0582,
    0xf3ba_0102,
    0xf3ba_0182,
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
    assert!(
        (0..4096)
            .step_by(4)
            .all(|a| memory.read_word(a).unwrap() == 0)
    );
    result
}

#[test]
fn reserved_misc_forms_precede_access_denials_without_effects() {
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
fn failed_thumb_it_suppresses_reserved_misc_operand_faults() {
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
fn mixed_width_reserved_misc_forms_do_not_become_higher_el_fp_traps() {
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

//! VFP scalar list/base decode constraints precede permission checks and effects.
use rax::isa::arm::aarch32::{cp15::Cpacr, cpu::ProcessorMode};
use rax::isa::arm::common::cpu::{ArmCpu, ArmError};
use rax::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, Mnemonic, ThumbDecoder};
use rax::isa::arm::execution::{ArmMemory, FlatMemory};
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};

fn word(double: bool, first: u32, words: u32, rn: u32, load: bool, mode: u32) -> u32 {
    let (p, u, w) = match mode {
        0 => (0, 1, 0),
        1 => (0, 1, 1),
        2 => (1, 0, 1),
        _ => unreachable!(),
    };
    let (d, vd) = if double {
        (first >> 4, first & 15)
    } else {
        (first & 1, first >> 1)
    };
    0xec00_0800
        | (p << 24)
        | (u << 23)
        | (d << 22)
        | (w << 21)
        | (u32::from(load) << 20)
        | (rn << 16)
        | (vd << 12)
        | (if double { 3 << 8 } else { 2 << 8 })
        | words
}
fn decode(raw: u32, thumb: bool) -> DecodedInsn {
    if thumb {
        ThumbDecoder::decode_32bit(raw).unwrap()
    } else {
        Aarch32Decoder::decode(raw).unwrap()
    }
}
fn block(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::VLDM | Mnemonic::VSTM | Mnemonic::VPUSH | Mnemonic::VPOP
    )
}
fn valid(double: bool, first: u32, words: u32) -> bool {
    let count = if double { words / 2 } else { words };
    count != 0 && first + count <= 32 && (!double || count <= 16)
}
#[test]
fn scalar_block_list_fields_are_validated_during_arm_and_thumb_decode() {
    for double in [false, true] {
        for first in 0..32 {
            for words in 0..256 {
                if double && words & 1 != 0 {
                    continue;
                } // Unsupported FLDMX/FSTMX frontier.
                for rn in [0, 13] {
                    for load in [false, true] {
                        for mode in 0..3 {
                            let raw = word(double, first, words, rn, load, mode);
                            for thumb in [false, true] {
                                let mnemonic = decode(raw, thumb).mnemonic;
                                if valid(double, first, words) {
                                    assert!(
                                        block(mnemonic),
                                        "{raw:08x}, thumb={thumb}: {mnemonic:?}"
                                    );
                                } else {
                                    assert_eq!(
                                        mnemonic,
                                        Mnemonic::UNDEFINED,
                                        "{raw:08x}, thumb={thumb}"
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
fn execute(raw: u32, thumb: bool, denial: u8, skipped: bool, invalid: bool) -> ExecResult {
    let mut cpu = Armv7Cpu::new();
    cpu.regs[0] = 0x800;
    cpu.regs[13] = 0x1000;
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
        cpu.cpsr.it_state = 0x18;
        cpu.cpsr.z = true;
    }
    cpu.vfp.dregs.fill(0x0123_4567_89ab_cdef);
    let before = (
        cpu.regs,
        cpu.vfp.dregs,
        cpu.vfp.fpscr.bits(),
        cpu.cpsr.to_u32(),
    );
    let mut memory = FlatMemory::new(8192, 0);
    let result = Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb));
    if invalid || denial != 0 || skipped {
        assert_eq!(
            (
                cpu.regs,
                cpu.vfp.dregs,
                cpu.vfp.fpscr.bits(),
                cpu.cpsr.to_u32()
            ),
            before,
            "raw={raw:08x}, thumb={thumb}, denial={denial}, skipped={skipped}"
        );
        assert!(
            (0..8192)
                .step_by(4)
                .all(|a| memory.read_word(a).unwrap() == 0)
        );
    } else {
        let rn = ((raw >> 16) & 15) as usize;
        if rn != 15 {
            let bytes = (raw & 255) * 4;
            let expected = if raw & (1 << 21) == 0 {
                before.0[rn]
            } else if raw & (1 << 23) != 0 {
                before.0[rn] + bytes
            } else {
                before.0[rn] - bytes
            };
            assert_eq!(cpu.regs[rn], expected, "{raw:08x}");
        }
    }
    result
}
fn edges() -> impl Iterator<Item = (bool, u32, u32)> {
    [
        (false, 31, 1),
        (false, 30, 2),
        (false, 31, 2),
        (false, 0, 32),
        (false, 1, 32),
        (false, 0, 0),
        (true, 31, 2),
        (true, 30, 4),
        (true, 31, 4),
        (true, 0, 32),
        (true, 16, 32),
        (true, 17, 32),
        (true, 0, 34),
        (true, 0, 0),
    ]
    .into_iter()
}
#[test]
fn scalar_block_boundary_operands_precede_access_faults_without_effects() {
    for (double, first, words) in edges() {
        for rn in [0, 13] {
            for load in [false, true] {
                for mode in 0..3 {
                    let raw = word(double, first, words, rn, load, mode);
                    for thumb in [false, true] {
                        for denial in 0..3 {
                            let invalid = !valid(double, first, words);
                            let result = execute(raw, thumb, denial, false, invalid);
                            if invalid {
                                assert!(
                                    matches!(result, ExecResult::Undefined),
                                    "{raw:08x}: {result:?}"
                                );
                            } else {
                                match denial {
                                    0 => assert!(
                                        matches!(result, ExecResult::Continue),
                                        "{raw:08x}: {result:?}"
                                    ),
                                    1 => assert!(
                                        matches!(result, ExecResult::Exception(_)),
                                        "{raw:08x}: {result:?}"
                                    ),
                                    _ => assert!(
                                        matches!(result, ExecResult::FpAccessTrap { .. }),
                                        "{raw:08x}: {result:?}"
                                    ),
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn scalar_block_pc_base_only_allows_arm_without_writeback() {
    for double in [false, true] {
        for load in [false, true] {
            for mode in 0..3 {
                let raw = word(double, 0, if double { 2 } else { 1 }, 15, load, mode);
                for thumb in [false, true] {
                    for denial in 0..3 {
                        let invalid = thumb || mode != 0;
                        let result = execute(raw, thumb, denial, false, invalid);
                        if invalid {
                            assert!(
                                matches!(result, ExecResult::Undefined),
                                "{raw:08x}, thumb={thumb}: {result:?}"
                            );
                        } else {
                            match denial {
                                0 => assert!(matches!(result, ExecResult::Continue)),
                                1 => assert!(matches!(result, ExecResult::Exception(_))),
                                _ => assert!(matches!(result, ExecResult::FpAccessTrap { .. })),
                            }
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn failed_thumb_it_suppresses_all_scalar_block_operand_failures() {
    for (double, first, words) in edges() {
        for load in [false, true] {
            for mode in 0..3 {
                for rn in [0, 13, 15] {
                    let raw = word(double, first, words, rn, load, mode);
                    assert!(matches!(
                        execute(raw, true, 2, true, true),
                        ExecResult::Continue
                    ));
                }
            }
        }
    }
}
#[test]
fn mixed_width_scalar_block_failures_do_not_retire_or_become_fp_traps() {
    for (double, first, words) in edges().filter(|(d, f, w)| !valid(*d, *f, *w)) {
        for load in [false, true] {
            for thumb in [false, true] {
                let raw = word(double, first, words, 0, load, 1);
                let mut cpu = super::mixed(raw, thumb, 2, false, true);
                let vector = cpu.get_simd(0);
                let result = cpu.step();
                assert!(
                    matches!(result,Err(ArmError::UndefinedInstruction(value)) if value==raw),
                    "{raw:08x}: {result:?}"
                );
                assert_eq!(cpu.get_pc(), 0x100);
                assert_eq!(cpu.instruction_count(), 0);
                assert_eq!(cpu.get_simd(0), vector);
            }
        }
    }
}
#[test]
fn unallocated_half_block_and_legacy_odd_double_lists_do_not_gain_fp_execution() {
    for thumb in [false, true] {
        for load in [false, true] {
            for mode in 0..3 {
                let single = word(false, 0, 2, 0, load, mode);
                assert!(!block(decode((single & !0x300) | 0x100, thumb).mnemonic));
                assert!(!block(
                    decode(word(true, 0, 3, 0, load, mode), thumb).mnemonic
                ));
            }
        }
    }
}

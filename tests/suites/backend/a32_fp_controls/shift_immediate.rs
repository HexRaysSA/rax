//! DDI0597 ID032025 Advanced SIMD immediate shifts: L:imm6 and zero counts.
use rax::isa::arm::aarch32::cp15::Cpacr;
use rax::isa::arm::aarch32::vfp::Fpscr;
use rax::isa::arm::common::cpu::{ArmCpu, ArmError};
use rax::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, Mnemonic, ThumbDecoder};
use rax::isa::arm::execution::FlatMemory;
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};

// Opcode, U, mnemonic. Right shifts use counts 1..=esize; left shifts use
// 0..esize. U selects signedness except for insert and signed-to-unsigned forms.
const OPERATIONS: [(u32, u32, Mnemonic); 14] = [
    (0, 0, Mnemonic::VSHR),
    (0, 1, Mnemonic::VSHR),
    (1, 0, Mnemonic::VSRA),
    (1, 1, Mnemonic::VSRA),
    (2, 0, Mnemonic::VRSHR),
    (2, 1, Mnemonic::VRSHR),
    (3, 0, Mnemonic::VRSRA),
    (3, 1, Mnemonic::VRSRA),
    (4, 1, Mnemonic::VSRI),
    (5, 0, Mnemonic::VSHL),
    (5, 1, Mnemonic::VSLI),
    (6, 1, Mnemonic::VQSHLU),
    (7, 0, Mnemonic::VQSHL),
    (7, 1, Mnemonic::VQSHL),
];

fn normalized(raw: u32, thumb: bool) -> u32 {
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

fn instruction(op: u32, u: u32, bits: u32, count: u32, q: u32, d: u32, m: u32) -> u32 {
    let immediate = if op <= 4 {
        2 * bits - count
    } else {
        bits + count
    };
    0xf280_0010
        | (u << 24)
        | ((immediate & 63) << 16)
        | ((immediate >> 6) << 7)
        | (op << 8)
        | (q << 6)
        | ((d >> 4) << 22)
        | ((d & 15) << 12)
        | ((m >> 4) << 5)
        | (m & 15)
}

fn cpu(thumb: bool) -> Armv7Cpu {
    let mut cpu = Armv7Cpu::new();
    cpu.cpsr.t = thumb;
    cpu.regs[15] = 0x800;
    cpu.cp15.cpacr = Cpacr::from_bits(0x00f0_0000);
    cpu.vfp.fpexc = 1 << 30;
    for (id, value) in cpu.vfp.dregs.iter_mut().enumerate() {
        *value = 0x9abc_def0_1234_5678u64.rotate_left(id as u32);
    }
    cpu
}

fn signed(value: u128, bits: u32) -> i128 {
    if value & (1u128 << (bits - 1)) != 0 {
        value as i128 - (1i128 << bits)
    } else {
        value as i128
    }
}

fn reference(source: u64, old: u64, op: u32, u: u32, bits: u32, count: u32) -> (u64, bool) {
    let mask = (1u128 << bits) - 1;
    let mut packed = 0u128;
    let mut saturated = false;
    for lane in 0..64 / bits {
        let source = (u128::from(source) >> (lane * bits)) & mask;
        let old = (u128::from(old) >> (lane * bits)) & mask;
        let value = match op {
            0..=3 => {
                let mut input = if u == 0 {
                    signed(source, bits)
                } else {
                    source as i128
                };
                if op >= 2 {
                    input += 1i128 << (count - 1);
                }
                let shifted = (input >> count) as u128;
                if op & 1 != 0 {
                    old.wrapping_add(shifted)
                } else {
                    shifted
                }
            }
            4 => {
                let inserted = mask >> count;
                (old & !inserted) | ((source >> count) & inserted)
            }
            5 if u == 0 => source << count,
            5 => (old & ((1u128 << count) - 1)) | (source << count),
            6 | 7 => {
                let input = if op == 6 || u == 0 {
                    signed(source, bits)
                } else {
                    source as i128
                };
                let shifted = input << count;
                let (minimum, maximum) = if op == 7 && u == 0 {
                    (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
                } else {
                    (0, mask as i128)
                };
                let result = shifted.clamp(minimum, maximum);
                saturated |= result != shifted;
                result as u128
            }
            _ => unreachable!(),
        } & mask;
        packed |= value << (lane * bits);
    }
    (packed as u64, saturated)
}

#[test]
fn every_immediate_count_matches_independent_integer_formulas() {
    for (op, u, mnemonic) in OPERATIONS {
        for bits in [8, 16, 32, 64] {
            for count in if op <= 4 { 1..=bits } else { 0..=bits - 1 } {
                for thumb in [false, true] {
                    for q in 0..2 {
                        for (d, m) in [(0, 0), (2, 4), (30, 28)] {
                            for pattern in [0, u64::MAX, 0x8000_7fff_0706_0505] {
                                let mut cpu = cpu(thumb);
                                cpu.vfp.dregs[m as usize] = pattern;
                                if q != 0 {
                                    cpu.vfp.dregs[m as usize + 1] = pattern.rotate_right(17);
                                }
                                cpu.vfp.fpscr = Fpscr::from_bits(0x11);
                                let mut expected = cpu.vfp.dregs;
                                let mut qc = false;
                                for register in 0..=q as usize {
                                    let (value, saturated) = reference(
                                        cpu.vfp.dregs[m as usize + register],
                                        expected[d as usize + register],
                                        op,
                                        u,
                                        bits,
                                        count,
                                    );
                                    expected[d as usize + register] = value;
                                    qc |= saturated;
                                }
                                let raw =
                                    normalized(instruction(op, u, bits, count, q, d, m), thumb);
                                let insn = decode(raw, thumb);
                                assert_eq!(insn.mnemonic, mnemonic, "raw={raw:08x}");
                                let regs = cpu.regs;
                                let cpsr = cpu.cpsr.to_u32();
                                let mut memory = FlatMemory::new(32, 0);
                                let result = Executor::new(&mut cpu, &mut memory).execute(&insn);
                                assert!(
                                    matches!(result, ExecResult::Continue),
                                    "raw={raw:08x}: {result:?}"
                                );
                                assert_eq!(
                                    cpu.vfp.dregs, expected,
                                    "raw={raw:08x}, pattern={pattern:016x}"
                                );
                                assert_eq!(
                                    cpu.vfp.fpscr.bits(),
                                    0x11 | if qc { 1 << 27 } else { 0 },
                                    "raw={raw:08x}"
                                );
                                assert_eq!(cpu.regs, regs);
                                assert_eq!(cpu.cpsr.to_u32(), cpsr);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn all_register_fields_preserve_d_q_alignment_at_every_lane_width_and_count() {
    for (op, u, mnemonic) in OPERATIONS {
        for bits in [8, 16, 32, 64] {
            for count in if op <= 4 { 1..=bits } else { 0..=bits - 1 } {
                for thumb in [false, true] {
                    for q in 0..2 {
                        for d in 0..32 {
                            for m in 0..32 {
                                let raw =
                                    normalized(instruction(op, u, bits, count, q, d, m), thumb);
                                let expected = if q != 0 && (d | m) & 1 != 0 {
                                    Mnemonic::UNDEFINED
                                } else {
                                    mnemonic
                                };
                                assert_eq!(decode(raw, thumb).mnemonic, expected, "raw={raw:08x}");
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn llvm_assembled_qemu_controls_match_exact_vectors_and_status() {
    let initial = 0x0706_0505_0302_0100;
    for (base, result, fpscr) in [
        (0xf288_0510, initial, 0),
        (0xf280_0590, initial, 0),
        (0xf3bf_0090, 0x0383_0282_8181_0080, 0),
        (0xf380_0090, 0, 0),
        (0xf380_0590, initial, 0),
        (0xf380_0490, initial, 0),
        (0xf280_0790, initial, 0),
        (0xf2bf_0790, 0x7fff_ffff_ffff_ffff, 1 << 27),
        (0xf380_0690, initial, 0),
    ] {
        for thumb in [false, true] {
            let mut cpu = cpu(thumb);
            cpu.vfp.dregs[0] = initial;
            cpu.vfp.dregs[1] = 0x9abc_def0_1234_5678;
            let mut expected = cpu.vfp.dregs;
            expected[0] = result;
            let raw = normalized(base, thumb);
            let mut memory = FlatMemory::new(32, 0);
            assert!(
                matches!(
                    Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb)),
                    ExecResult::Continue
                ),
                "raw={raw:08x}"
            );
            assert_eq!(cpu.vfp.dregs, expected, "raw={raw:08x}");
            assert_eq!(cpu.vfp.fpscr.bits(), fpscr, "raw={raw:08x}");
        }
    }
}

#[test]
fn signed_to_unsigned_zero_shift_saturates_and_qc_remains_sticky() {
    for bits in [8, 16, 32, 64] {
        for thumb in [false, true] {
            let mut cpu = cpu(thumb);
            cpu.vfp.dregs[0] = u64::MAX;
            cpu.vfp.fpscr = Fpscr::from_bits(0x11);
            let raw = normalized(instruction(6, 1, bits, 0, 0, 0, 0), thumb);
            let mut memory = FlatMemory::new(32, 0);
            for _ in 0..2 {
                assert!(matches!(
                    Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb)),
                    ExecResult::Continue
                ));
                assert_eq!(cpu.vfp.dregs[0], 0);
                assert_eq!(cpu.vfp.fpscr.bits(), (1 << 27) | 0x11);
            }
        }
    }
}

#[test]
fn legal_immediate_forms_reach_access_traps_and_failed_it_suppresses_effects() {
    for (op, u, _) in OPERATIONS {
        for bits in [8, 16, 32, 64] {
            let count = if op <= 4 { bits } else { 0 };
            for thumb in [false, true] {
                let raw = normalized(instruction(op, u, bits, count, 0, 0, 0), thumb);
                let mut cpu = cpu(thumb);
                cpu.cp15.cpacr = Cpacr::from_bits(0);
                cpu.vfp.fpexc = 0;
                let before = cpu.vfp.dregs;
                let mut memory = FlatMemory::new(32, 0);
                assert!(
                    matches!(
                        Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb)),
                        ExecResult::Exception(_)
                    ),
                    "raw={raw:08x}"
                );
                assert_eq!(cpu.vfp.dregs, before);
                if thumb {
                    cpu.cpsr.it_state = 0x18;
                    cpu.cpsr.z = true;
                    assert!(matches!(
                        Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb)),
                        ExecResult::Continue
                    ));
                    assert_eq!(cpu.vfp.dregs, before);
                }
            }
        }
    }
}

#[test]
fn mixed_width_legal_shifts_select_fp_traps_before_zero_retirement_effects() {
    for (op, u, _) in OPERATIONS {
        for thumb in [false, true] {
            let count = if op <= 4 { 64 } else { 0 };
            let raw = normalized(instruction(op, u, 64, count, 0, 0, 0), thumb);
            let mut cpu = super::mixed(raw, thumb, 2, false, true);
            let before = cpu.get_simd(0);
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
            assert_eq!(cpu.get_simd(0), before);
            assert_eq!(cpu.get_pc(), 0x100);
            assert_eq!(cpu.instruction_count(), 0);
        }
    }
}

#[test]
fn reserved_fixed_selectors_are_undefined_before_fp_access() {
    // VSRI has fixed U=1; the VQSHL/VQSHLU class explicitly rejects U:op=00.
    // Each partition also executes as Undefined in the independent QEMU guest.
    for op in [4, 6] {
        for bits in [8, 64] {
            let count = if op == 4 { bits } else { 0 };
            for thumb in [false, true] {
                let raw = normalized(instruction(op, 0, bits, count, 0, 0, 0), thumb);
                assert_eq!(
                    decode(raw, thumb).mnemonic,
                    Mnemonic::UNDEFINED,
                    "raw={raw:08x}"
                );
                for denied in [false, true] {
                    let mut cpu = cpu(thumb);
                    if denied {
                        cpu.cp15.cpacr = Cpacr::from_bits(0);
                    }
                    let before = cpu.vfp.dregs;
                    let mut memory = FlatMemory::new(32, 0);
                    assert!(matches!(
                        Executor::new(&mut cpu, &mut memory).execute(&decode(raw, thumb)),
                        ExecResult::Undefined
                    ));
                    assert_eq!(cpu.vfp.dregs, before);
                }
            }
        }
    }
}

#[test]
fn modified_immediate_and_narrowing_widening_neighbors_keep_their_allocation() {
    for thumb in [false, true] {
        // L:imm6=0000xxx selects modified immediates. Here op=0 in that
        // encoding class, so even cmode selects VMOV and odd cmode VORR.
        for immediate in 0..8 {
            for cmode in 0..8 {
                for i in 0..2 {
                    for q in 0..2 {
                        for d in 0..32 {
                            let raw = normalized(
                                0xf280_0010
                                    | (i << 24)
                                    | (immediate << 16)
                                    | (cmode << 8)
                                    | (q << 6)
                                    | ((d >> 4) << 22)
                                    | ((d & 15) << 12),
                                thumb,
                            );
                            let expected = if q != 0 && d & 1 != 0 {
                                Mnemonic::UNDEFINED
                            } else if cmode & 1 != 0 {
                                Mnemonic::VORR
                            } else {
                                Mnemonic::VMOV
                            };
                            assert_eq!(decode(raw, thumb).mnemonic, expected, "raw={raw:08x}");
                        }
                    }
                }
            }
        }
        for bits in [8, 16, 32] {
            for (op, u, rounding, mnemonic) in [
                (8, 0, 0, Mnemonic::VSHRN),
                (8, 0, 1, Mnemonic::VRSHRN),
                (8, 1, 0, Mnemonic::VQSHRUN),
                (8, 1, 1, Mnemonic::VQRSHRUN),
                (9, 0, 0, Mnemonic::VQSHRN),
                (9, 0, 1, Mnemonic::VQRSHRN),
                (9, 1, 0, Mnemonic::VQSHRN),
                (9, 1, 1, Mnemonic::VQRSHRN),
            ] {
                for count in 1..=bits {
                    for d in 0..32 {
                        for m in 0..32 {
                            let raw = normalized(
                                instruction(op, u, bits, 0, rounding, d, m) & !0x003f_0000
                                    | ((2 * bits - count) << 16),
                                thumb,
                            );
                            assert_eq!(
                                decode(raw, thumb).mnemonic,
                                if m & 1 == 0 {
                                    mnemonic
                                } else {
                                    Mnemonic::UNDEFINED
                                },
                                "raw={raw:08x}"
                            );
                        }
                    }
                }
            }
            for u in 0..2 {
                for d in 0..32 {
                    for m in 0..32 {
                        let raw = normalized(instruction(10, u, bits, 0, 0, d, m), thumb);
                        assert_eq!(
                            decode(raw, thumb).mnemonic,
                            if d & 1 == 0 {
                                Mnemonic::VMOVL
                            } else {
                                Mnemonic::UNDEFINED
                            },
                            "raw={raw:08x}"
                        );
                    }
                }
            }
        }
    }
}

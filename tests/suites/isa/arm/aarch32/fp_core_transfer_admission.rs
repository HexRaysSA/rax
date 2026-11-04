//! Arm ASL VMOV_s/VMOV_rs/VMOV_sr decode constraints and selected Undefined policy.
use rax::isa::arm::aarch32::cp15::Cpacr;
use rax::isa::arm::aarch32::vfp::Fpscr;
use rax::isa::arm::decoder::{Aarch32Decoder, DecodedInsn, Mnemonic, ThumbDecoder};
use rax::isa::arm::execution::FlatMemory;
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};

// LLVM23 ARM/Thumb anchors and primary ASL provenance are retained alongside
// the qualification receipt. Fields: word, element bits, read, unsigned.
const CASES: &[(u32, u32, bool, bool)] = &[
    (0xee00_0a10, 32, false, true),
    (0xee10_0a10, 32, true, true),
    (0xee00_0b10, 32, false, true),
    (0xee10_0b10, 32, true, true),
    (0xee00_0b30, 16, false, true),
    (0xee10_0b30, 16, true, false),
    (0xee90_0b30, 16, true, true),
    (0xee40_0b10, 8, false, true),
    (0xee50_0b10, 8, true, false),
    (0xeed0_0b10, 8, true, true),
];

fn decode(raw: u32, thumb: bool) -> DecodedInsn {
    if thumb {
        ThumbDecoder::decode_32bit(raw)
    } else {
        Aarch32Decoder::decode(raw)
    }
    .unwrap()
}

fn execute(cpu: &mut Armv7Cpu, instruction: &DecodedInsn) -> ExecResult {
    let mut memory = FlatMemory::new(4096, 0);
    Executor::new(cpu, &mut memory).execute(instruction)
}

#[test]
fn r15_core_transfers_select_undefined_before_access_and_preserve_state() {
    for thumb in [false, true] {
        for access in [false, true] {
            for enabled in [false, true] {
                for &(word, bits, _, _) in CASES {
                    let single = (word >> 8) & 15 == 10;
                    for fp in [0, 15, 16, 31] {
                        for last_lane in [false, true] {
                            let bank = if single {
                                ((fp >> 1) << 16) | ((fp & 1) << 7)
                            } else {
                                ((fp & 15) << 16) | ((fp >> 4) << 7)
                            };
                            let mut raw = (word & !0x000f_0080) | bank | 0xf000;
                            if last_lane && !single {
                                raw |= 1 << 21;
                                if bits != 32 {
                                    raw |= 1 << 6;
                                    if bits == 8 {
                                        raw |= 1 << 5;
                                    }
                                }
                            }
                            let instruction = decode(raw, thumb);
                            assert_eq!(instruction.mnemonic, Mnemonic::UNDEFINED, "{raw:08x}");
                            let mut cpu = Armv7Cpu::new();
                            cpu.cpsr.t = thumb;
                            cpu.cp15.cpacr = Cpacr::from_bits(if access { 0x00f0_0000 } else { 0 });
                            cpu.vfp.fpexc = if enabled { 1 << 30 } else { 0 };
                            cpu.vfp.fpscr = Fpscr::from_bits(0xa800_009f);
                            let before = (
                                cpu.regs,
                                cpu.vfp.dregs,
                                cpu.vfp.fpscr.bits(),
                                cpu.cpsr.to_u32(),
                            );
                            assert!(matches!(
                                execute(&mut cpu, &instruction),
                                ExecResult::Undefined
                            ));
                            assert_eq!(
                                (
                                    cpu.regs,
                                    cpu.vfp.dregs,
                                    cpu.vfp.fpscr.bits(),
                                    cpu.cpsr.to_u32()
                                ),
                                before
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn valid_core_transfers_preserve_width_signedness_and_neighbor_bits() {
    // These 216 cases independently match QEMU Cortex-A15, including
    // every D register and FPSCR, in the retained qualification observations.
    for thumb in [false, true] {
        for &(word, bits, read, unsigned) in CASES {
            let single = (word >> 8) & 15 == 10;
            for fp in [0, 31] {
                for last_lane in [false, true] {
                    if single && last_lane {
                        continue;
                    }
                    for rt in [0, 12, 14] {
                        let bank = if single {
                            ((fp >> 1) << 16) | ((fp & 1) << 7)
                        } else {
                            ((fp & 15) << 16) | ((fp >> 4) << 7)
                        };
                        let mut raw = (word & !0x000f_0080) | bank | (rt << 12);
                        if last_lane && !single {
                            raw |= 1 << 21;
                            if bits != 32 {
                                raw |= 1 << 6;
                                if bits == 8 {
                                    raw |= 1 << 5;
                                }
                            }
                        }
                        let instruction = decode(raw, thumb);
                        assert_eq!(instruction.mnemonic, Mnemonic::VMOV);
                        let mut cpu = Armv7Cpu::new();
                        cpu.cpsr.t = thumb;
                        cpu.regs[0] = 0x1020_3040;
                        cpu.regs[12] = 0x5060_7080;
                        cpu.regs[14] = 0x90a0_b0c0;
                        cpu.regs[rt as usize] = 0xdead_89a5;
                        for (index, vector) in cpu.vfp.dregs.iter_mut().enumerate() {
                            *vector =
                                0x8877_6655_90f0_b180 ^ (index as u64 * 0x0101_0101_0101_0101);
                        }
                        cpu.vfp.fpscr = Fpscr::from_bits(0xa800_009f);
                        let mut registers = cpu.regs;
                        let mut vectors = cpu.vfp.dregs;
                        let psr = cpu.cpsr.to_u32();
                        let index = if single { fp / 2 } else { fp } as usize;
                        let shift = if single {
                            (fp & 1) * 32
                        } else if last_lane {
                            64 - bits
                        } else {
                            0
                        };
                        let mask = (1u64 << bits) - 1;
                        if read {
                            let value = (vectors[index] >> shift) & mask;
                            registers[rt as usize] = if unsigned {
                                value as u32
                            } else {
                                ((value << (64 - bits)) as i64 >> (64 - bits)) as u32
                            };
                        } else {
                            vectors[index] = (vectors[index] & !(mask << shift))
                                | ((u64::from(registers[rt as usize]) & mask) << shift);
                        }
                        assert!(matches!(
                            execute(&mut cpu, &instruction),
                            ExecResult::Continue
                        ));
                        assert_eq!(cpu.regs, registers, "{raw:08x} thumb={thumb}");
                        assert_eq!(cpu.vfp.dregs, vectors, "{raw:08x} thumb={thumb}");
                        assert_eq!(cpu.vfp.fpscr.bits(), 0xa800_009f);
                        assert_eq!(cpu.cpsr.to_u32(), psr);
                    }
                }
            }
        }
    }
}

#[test]
fn failed_arm_conditions_keep_invalid_transfer_operands_without_effects() {
    for &(word, _, _, _) in CASES {
        for access in [false, true] {
            let instruction = decode((word & 0x0fff_ffff) | 0xf000, false);
            let mut cpu = Armv7Cpu::new();
            cpu.cpsr.z = false;
            cpu.cp15.cpacr = Cpacr::from_bits(if access { 0x00f0_0000 } else { 0 });
            let before = (cpu.regs, cpu.vfp.dregs, cpu.cpsr.to_u32());
            assert!(matches!(
                execute(&mut cpu, &instruction),
                ExecResult::Continue
            ));
            assert_eq!((cpu.regs, cpu.vfp.dregs, cpu.cpsr.to_u32()), before);
        }
    }
}

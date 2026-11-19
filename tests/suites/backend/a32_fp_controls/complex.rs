//! Arm DDI0597 VCADD and VCMLA in A32 and T32.
use super::*;
use rax::isa::arm::common::features::ArmFeatures;
use rax::isa::arm::decoder::{Mnemonic, ThumbDecoder};

const VCMA: u32 = 1 << 28;
const ID_ISAR5: u32 = 0xee10_0fb2; // MRC P15,0,R0,C0,C2,5.
const ADD_D_F32: u32 = 0xfc91_0802; // VCADD.F32 D0,D1,D2,#90.
const ADD_Q_F16: u32 = 0xfd82_0844; // VCADD.F16 Q0,Q1,Q2,#270.
const ACC_Q_F32: u32 = 0xfd32_0844; // VCMLA.F32 Q0,Q1,Q2,#180.
const INDEXED_Q_F32: u32 = 0xfe92_0864; // VCMLA.F32 Q0,Q1,D20[0],#90.
const INPUT: [u64; 3] = [0, 0x4040_0000_4000_0000, 0x40e0_0000_40a0_0000];

fn decoded(raw: u32, thumb: bool) -> rax::isa::arm::decoder::DecodedInsn {
    // The A1 and T1 encodings have identical architectural bit positions.
    if thumb {
        ThumbDecoder::decode_32bit(raw)
    } else {
        Aarch32Decoder::decode(raw)
    }
    .unwrap()
}

fn operation(cpu: &mut Armv7Cpu, raw: u32) -> ExecResult {
    let insn = decoded(raw, cpu.cpsr.t);
    Executor::new(cpu, &mut Memory32::new(4096, 0)).execute(&insn)
}

#[test]
fn complex_add_executes_with_vcma_in_arm_and_thumb() {
    for thumb in [false, true] {
        let mut cpu = Armv7Cpu::new();
        cpu.cp15.id_isar[5] |= VCMA;
        cpu.cpsr.t = thumb;
        cpu.vfp.dregs[..INPUT.len()].copy_from_slice(&INPUT);
        let result = operation(&mut cpu, ADD_D_F32);
        assert!(
            matches!(result, ExecResult::Continue),
            "{thumb}: {result:?}"
        );
        assert_eq!(
            cpu.vfp.dregs[..3],
            [0x4100_0000_c0a0_0000, INPUT[1], INPUT[2]]
        );
    }
}

#[test]
fn complex_id_and_dependencies_precede_access_traps() {
    for thumb in [false, true] {
        for vcma in [0, 1, 2, 15] {
            for dependencies in [0, 1, 2, 3, 4] {
                let mut cpu = hyp();
                cpu.cpsr.t = thumb;
                cpu.cp15.id_isar[5] = (vcma << 28) | (1 << 24);
                match dependencies {
                    1 => cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !15) | 1, // D16
                    2 => cpu.vfp.mvfr1 &= !(15 << 12),              // No SIMDInt
                    3 => cpu.vfp.mvfr1 &= !(15 << 16),              // No SIMDSP
                    4 => cpu.vfp.mvfr1 &= !(1 << 21),               // SIMDHP conversion only
                    _ => (),
                }
                let full = vcma == 1 && matches!(dependencies, 0 | 4);
                assert!(matches!(
                    operation(&mut cpu, ID_ISAR5),
                    ExecResult::Continue
                ));
                let rdm = u32::from(!matches!(dependencies, 1 | 2)) << 24;
                assert_eq!(cpu.regs[0], (u32::from(full) << 28) | rdm);
                // Reserved or incompatible profile fields stay intact.
                assert_eq!(cpu.cp15.id_isar[5], (vcma << 28) | (1 << 24));
                cpu.cp15.hcptr |= 1 << 10;
                let before = cpu.vfp.dregs;
                let fpscr = cpu.vfp.fpscr.bits();
                for word in [ADD_D_F32, ADD_Q_F16, ACC_Q_F32, INDEXED_Q_F32] {
                    let result = operation(&mut cpu, word);
                    if full && (word != ADD_Q_F16 || dependencies != 4) {
                        assert!(matches!(
                            result,
                            ExecResult::FpAccessTrap { target_el: 2, .. }
                        ));
                    } else {
                        assert!(matches!(result, ExecResult::Undefined));
                    }
                    assert_eq!(cpu.vfp.dregs, before);
                    assert_eq!(cpu.vfp.fpscr.bits(), fpscr);
                }
            }
        }
    }
}

#[test]
fn complex_q_alignment_and_thumb_predication_precede_access() {
    for thumb in [false, true] {
        for invalid in [
            ADD_Q_F16 | (1 << 12),
            ACC_Q_F32 | (1 << 16),
            ACC_Q_F32 | 1,
            INDEXED_Q_F32 | (1 << 12),
            INDEXED_Q_F32 | (1 << 16),
        ] {
            assert_eq!(decoded(invalid, thumb).mnemonic, Mnemonic::UNDEFINED);
        }
        // An indexed Dm is legal even when it is odd and Q=1.
        assert_eq!(decoded(INDEXED_Q_F32 | 1, thumb).mnemonic, Mnemonic::VCMLA);
    }
    for raw in [ADD_D_F32, ACC_Q_F32, INDEXED_Q_F32] {
        for executes in [false, true] {
            let mut cpu = hyp();
            cpu.cp15.id_isar[5] = VCMA;
            cpu.cpsr.t = true;
            cpu.cpsr.it_state = 0x08; // IT EQ.
            cpu.cpsr.z = executes;
            cpu.cp15.hcptr |= 1 << 10;
            let before = cpu.vfp.dregs;
            let result = operation(&mut cpu, raw);
            assert!(if executes {
                matches!(result, ExecResult::Undefined)
            } else {
                matches!(result, ExecResult::Continue)
            });
            assert_eq!(cpu.vfp.dregs, before);
        }
    }
}

#[test]
fn complex_mixed_width_id_readback_controls_retirement() {
    for field in [0u64, 1, 2] {
        for thumb in [false, true] {
            let mut cpu = mixed(ID_ISAR5, thumb, 2, false, true);
            let mut state = cpu.export_sregs();
            let execution = state.execution.as_mut().unwrap();
            // Import derives the architecture IDs from the saved feature set.
            if field == 1 {
                execution.features |= ArmFeatures::FCMA.bits();
            }
            let sys = &mut execution.sysregs;
            sys.id_aa64isar1_el1 = (sys.id_aa64isar1_el1 & !(15 << 16)) | (field << 16);
            sys.impl_defined
                .remove(&Aarch64SysRegEncoding::new(3, 4, 1, 1, 2).encode());
            let isar5 = Aarch64SysRegEncoding::new(3, 0, 0, 2, 5);
            let reported = u64::from(field == 1) << 28;
            assert_eq!(
                sys.read(isar5, 1).unwrap() & u64::from(15u32 << 28),
                reported
            );
            if field == 2 {
                assert!(matches!(
                    cpu.import_sregs(&state),
                    Err(ArmError::Configuration(message)) if message.contains("unsupported optional FP/SIMD ID level")
                ));
                assert_eq!(cpu.get_pc(), 0x100);
                assert_eq!(cpu.instruction_count(), 0);
                continue;
            }
            cpu.import_sregs(&state).unwrap();
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(cpu.get_x(0) & u64::from(15u32 << 28), reported);

            let encoded = if thumb {
                ADD_D_F32.rotate_left(16)
            } else {
                ADD_D_F32
            };
            cpu.write_memory(0x104, &encoded.to_le_bytes()).unwrap();
            let prior_q = u128::from(INPUT[1]) << 64;
            cpu.set_simd(0, prior_q);
            cpu.set_simd(1, u128::from(INPUT[2]));
            let prior_count = cpu.instruction_count();
            if field == 1 {
                assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
                assert_eq!(cpu.get_simd(0), prior_q | 0x4100_0000_c0a0_0000);
                assert_eq!(cpu.instruction_count(), prior_count + 1);
            } else {
                assert!(matches!(
                    cpu.step(),
                    Err(ArmError::UndefinedInstruction(ADD_D_F32))
                ));
                assert_eq!(cpu.get_simd(0), prior_q);
                assert_eq!(cpu.instruction_count(), prior_count);
                assert_eq!(cpu.get_pc(), 0x104);
            }
        }
    }
}

#[test]
fn complex_arithmetic_matches_independent_qemu_vectors() {
    // D0-D5 and D20. A1 and T1 gave identical results in the oracle.
    let half = [
        0x4400_4200_4000_3c00,
        0x4a80_4980_4700_4500,
        0x4f40_4dc0_4cc0_4c40,
        0x5160_5120_50a0_4fc0,
        0x53a0_5360_52a0_51e0,
        0x54f0_5490_5470_5430,
        0x5650_5610_5590_5530,
    ];
    let single = [
        0x4000_0000_3f80_0000,
        0x4080_0000_4040_0000,
        0x40e0_0000_40a0_0000,
        0x4150_0000_4130_0000,
        0x4198_0000_4188_0000,
        0x41e8_0000_41b8_0000,
        0x4214_0000_41f8_0000,
    ];
    let fixtures = include_str!("complex-qemu.tsv");
    assert_eq!(fixtures.lines().count(), 45);
    for line in fixtures.lines().skip(1) {
        let columns: Vec<_> = line.split('\t').collect();
        let [word, profile, d0, d1, status, asm] = &columns[..] else {
            panic!("invalid oracle row {line}");
        };
        let raw = u32::from_str_radix(word, 16).unwrap();
        let (registers, fpscr) = match *profile {
            "half" => (half, 0x08c0_0010),
            "single" => (single, 0x08c0_0010),
            "fused" => ([0xbf80_0000, 0x3f80_0001, 0x3f7f_fffe, 0, 0, 0, 0], 0),
            "single-special" => ([0, 0x7fa0_0000_0000_0001, 0, 0, 0, 0, 0], 0x0400_0010),
            "half-special" => ([0, 0x7c01_7e01_0001_8001, 0, 0, 0, 0, 0], 0),
            "half-flushed" => ([0, 0x7c01_7e01_0001_8001, 0, 0, 0, 0, 0], 1 << 19),
            _ => panic!("unrecognized oracle input {profile}"),
        };
        for thumb in [false, true] {
            let mut cpu = Armv7Cpu::new();
            cpu.cp15.id_isar[5] = VCMA;
            cpu.cpsr.t = thumb;
            cpu.vfp.dregs.fill(0xcafe_babe);
            cpu.vfp.dregs[..6].copy_from_slice(&registers[..6]);
            cpu.vfp.dregs[20] = registers[6];
            cpu.vfp.fpscr = rax::isa::arm::aarch32::vfp::Fpscr::from_bits(fpscr);
            let mut expected = cpu.vfp.dregs;
            expected[0] = u64::from_str_radix(d0, 16).unwrap();
            expected[1] = u64::from_str_radix(d1, 16).unwrap();
            let result = operation(&mut cpu, raw);
            assert!(
                matches!(result, ExecResult::Continue),
                "{asm}, Thumb={thumb}: {result:?}"
            );
            assert_eq!(cpu.vfp.dregs, expected, "{asm}, Thumb={thumb}");
            assert_eq!(
                cpu.vfp.fpscr.bits(),
                u32::from_str_radix(status, 16).unwrap(),
                "{asm}, Thumb={thumb}"
            );
        }
    }
}

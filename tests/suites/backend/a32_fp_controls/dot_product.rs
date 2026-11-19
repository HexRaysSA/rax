//! Arm DDI0597 VSDOT and VUDOT in A32 and T32.
use super::*;
use rax::isa::arm::decoder::ThumbDecoder;

const DP: u32 = 1 << 4;
const SDOT_D: u32 = 0xfc22_0d04; // VSDOT.S8 D0, D2, D4.

fn decoded(raw: u32, thumb: bool) -> rax::isa::arm::decoder::DecodedInsn {
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
fn dot_product_executes_with_dp_in_arm_and_thumb() {
    for thumb in [false, true] {
        let mut cpu = Armv7Cpu::new();
        cpu.cp15.id_isar6 |= DP;
        cpu.cpsr.t = thumb;
        cpu.vfp.dregs[0] = 0x0000_0002_0000_0001;
        cpu.vfp.dregs[2] = 0x0403_0201_0403_0201;
        cpu.vfp.dregs[4] = 0x0102_0304_0102_0304;
        let result = operation(&mut cpu, SDOT_D);
        assert!(
            matches!(result, ExecResult::Continue),
            "{thumb}: {result:?}"
        );
        assert_eq!(cpu.vfp.dregs[0], 0x0000_0016_0000_0015);
    }
}

const ID_ISAR6: u32 = 0xee10_0ff2; // MRC P15,0,R0,C0,C2,7.
const UDOT_Q: u32 = 0xfc22_0d54; // VUDOT.U8 Q0, Q1, Q2.
const INDEXED_Q: u32 = 0xfe22_0d64; // VSDOT.S8 Q0, Q1, D4[1].

#[test]
fn dp_report_and_admission_agree_before_the_access_trap() {
    for thumb in [false, true] {
        for level in [0, 1, 2, 15] {
            for restriction in [0, 1, 2, 3] {
                let mut cpu = hyp();
                cpu.cpsr.t = thumb;
                let raw = (level << 4) | 0x101;
                cpu.cp15.id_isar6 = raw;
                match restriction {
                    1 => cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !15) | 1, // D16
                    2 => cpu.vfp.mvfr1 &= !(15 << 12),              // No SIMDInt
                    3 => cpu.vfp.mvfr1 &= !((15 << 16) | (15 << 20)), // No SIMD floating point
                    _ => (),
                }
                let available = level == 1 && matches!(restriction, 0 | 3);
                assert!(matches!(
                    operation(&mut cpu, ID_ISAR6),
                    ExecResult::Continue
                ));
                assert_eq!(cpu.regs[0] & (15 << 4), if available { DP } else { 0 });
                assert_eq!(cpu.cp15.id_isar6, raw);

                cpu.cp15.hcptr |= 1 << 10;
                let registers = cpu.vfp.dregs;
                let fpscr = cpu.vfp.fpscr.bits();
                for word in [SDOT_D, UDOT_Q, INDEXED_Q] {
                    let result = operation(&mut cpu, word);
                    assert!(
                        if available {
                            matches!(result, ExecResult::FpAccessTrap { target_el: 2, .. })
                        } else {
                            matches!(result, ExecResult::Undefined)
                        },
                        "DP={level}, profile={restriction}, Thumb={thumb}: {result:?}"
                    );
                    assert_eq!(cpu.vfp.dregs, registers);
                    assert_eq!(cpu.vfp.fpscr.bits(), fpscr);
                }
            }
        }
    }
}

#[test]
fn invalid_q_pairs_and_executed_it_slots_are_undefined() {
    use rax::isa::arm::decoder::Mnemonic;

    for thumb in [false, true] {
        for raw in [
            UDOT_Q | (1 << 12),
            UDOT_Q | (1 << 16),
            UDOT_Q | 1,
            INDEXED_Q | (1 << 12),
            INDEXED_Q | (1 << 16),
        ] {
            assert_eq!(decoded(raw, thumb).mnemonic, Mnemonic::UNDEFINED);
        }
        // A single indexed Dm may be odd even when Dd and Dn are Q pairs.
        assert_eq!(decoded(INDEXED_Q | 1, thumb).mnemonic, Mnemonic::VSDOT);
    }
    for raw in [SDOT_D, UDOT_Q, INDEXED_Q] {
        for executes in [false, true] {
            let mut cpu = hyp();
            cpu.cp15.id_isar6 |= DP;
            cpu.cpsr.t = true;
            cpu.cpsr.it_state = 0x08; // IT EQ.
            cpu.cpsr.z = executes;
            cpu.cp15.hcptr |= 1 << 10;
            let before = cpu.vfp.dregs;
            let result = operation(&mut cpu, raw);
            assert!(
                if executes {
                    matches!(result, ExecResult::Undefined)
                } else {
                    matches!(result, ExecResult::Continue)
                },
                "{raw:#010x}: {result:?}"
            );
            assert_eq!(cpu.vfp.dregs, before);
        }
    }
}

#[test]
fn mixed_pe_reports_dp_and_retires_only_when_the_saved_profile_enables_it() {
    use rax::isa::arm::common::features::ArmFeatures;

    for thumb in [false, true] {
        for enabled in [false, true] {
            let mut cpu = mixed(ID_ISAR6, thumb, 2, false, true);
            let mut state = cpu.export_sregs();
            let execution = state.execution.as_mut().unwrap();
            let mut features = ArmFeatures::from_bits_retain(execution.features);
            features.set(ArmFeatures::DOTPROD, enabled);
            execution.features = features.bits();
            let sys = &mut execution.sysregs;
            sys.id_aa64isar0_el1 =
                (sys.id_aa64isar0_el1 & !(15 << 44)) | (u64::from(enabled) << 44);
            sys.impl_defined
                .remove(&Aarch64SysRegEncoding::new(3, 4, 1, 1, 2).encode());
            let encoding = Aarch64SysRegEncoding::new(3, 0, 0, 2, 7);
            let expected = if enabled { u64::from(DP) } else { 0 };
            assert_eq!(sys.read(encoding, 1).unwrap() & (15 << 4), expected);
            cpu.import_sregs(&state).unwrap();
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(cpu.get_x(0) & (15 << 4), expected);

            let encoded = if thumb {
                SDOT_D.rotate_left(16)
            } else {
                SDOT_D
            };
            cpu.write_memory(0x104, &encoded.to_le_bytes()).unwrap();
            let upper = 0x1122_3344_5566_7788u128 << 64;
            let before = upper | 0x0000_0002_0000_0001;
            cpu.set_simd(0, before);
            cpu.set_simd(1, 0x0403_0201_0403_0201);
            cpu.set_simd(2, 0x0102_0304_0102_0304);
            let retired = cpu.instruction_count();
            if enabled {
                assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
                assert_eq!(cpu.get_simd(0), upper | 0x0000_0016_0000_0015);
                assert_eq!(cpu.instruction_count(), retired + 1);
            } else {
                assert!(matches!(
                    cpu.step(),
                    Err(ArmError::UndefinedInstruction(SDOT_D))
                ));
                assert_eq!(cpu.get_simd(0), before);
                assert_eq!(cpu.instruction_count(), retired);
                assert_eq!(cpu.get_pc(), 0x104);
            }
        }
    }
}

#[test]
fn dot_arithmetic_matches_independent_qemu_vectors() {
    use rax::isa::arm::aarch32::vfp::Fpscr;

    const REGISTERS: [u64; 7] = [
        0x7fff_fff8_ffff_fff0,
        0x8000_0001_ffff_fffe,
        0x8180_7fff_0403_0201,
        0x00fe_807e_eb97_8704,
        0x017f_80ff_8001_8001,
        0xfffe_01ff_fd80_a580,
        0xec0c_83ff_aca0_807f,
    ];
    const FPSCR: u32 = 0xf8c0_0010;
    let fixtures = include_str!("dot-product-qemu.tsv");
    assert_eq!(fixtures.lines().count(), 19);
    for line in fixtures.lines().skip(1) {
        let columns: Vec<_> = line.split('\t').collect();
        let [word, d0, d1, d2, d3, d4, d5, d20, assembly] = columns[..] else {
            panic!("invalid oracle row {line}");
        };
        let raw = u32::from_str_radix(word, 16).unwrap();
        for thumb in [false, true] {
            let mut cpu = Armv7Cpu::new();
            cpu.cp15.id_isar6 |= DP;
            cpu.cpsr.t = thumb;
            cpu.cpsr.n = true;
            cpu.cpsr.c = true;
            cpu.vfp.fpscr = Fpscr::from_bits(FPSCR);
            let initial_pstate = cpu.cpsr.to_u32();
            cpu.vfp.dregs.fill(0x55aa_55aa_55aa_55aa);
            cpu.vfp.dregs[..6].copy_from_slice(&REGISTERS[..6]);
            cpu.vfp.dregs[20] = REGISTERS[6];
            let mut expected = cpu.vfp.dregs;
            for (reg, value) in [0, 1, 2, 3, 4, 5, 20]
                .into_iter()
                .zip([d0, d1, d2, d3, d4, d5, d20])
            {
                expected[reg] = u64::from_str_radix(value, 16).unwrap();
            }
            let result = operation(&mut cpu, raw);
            assert!(
                matches!(result, ExecResult::Continue),
                "{assembly}, Thumb={thumb}: {result:?}"
            );
            assert_eq!(cpu.vfp.dregs, expected, "{assembly}, Thumb={thumb}");
            assert_eq!(cpu.vfp.fpscr.bits(), FPSCR);
            assert_eq!(cpu.cpsr.to_u32(), initial_pstate);
        }
    }
}

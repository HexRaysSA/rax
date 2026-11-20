//! Arm DDI0597 A32 and T32 FEAT_AA32I8MM profile boundaries.
use super::*;
use rax::isa::arm::aarch32::vfp::Fpscr;
use rax::isa::arm::common::features::ArmFeatures;
use rax::isa::arm::decoder::{DecodedInsn, Mnemonic, ThumbDecoder};

const I8MM: u32 = 1 << 24;
const SMMLA: u32 = 0xfc22_0c44; // VSMMLA.S8 Q0, Q1, Q2.
const USDOT: u32 = 0xfca2_0d44; // VUSDOT.S8 Q0, Q1, Q2.
const SUDOT_INDEXED: u32 = 0xfe82_0d74; // VSUDOT.U8 Q0, Q1, D4[1].
const ISAR6: u32 = 0xee10_0ff2;
const MATRIX_INPUT: [u64; 6] = [
    0x0000_0002_0000_0001,
    0x0000_0004_0000_0003,
    0xffff_ffff_ffff_ffff,
    0x0202_0202_0202_0202,
    0x0303_0303_0303_0303,
    0xfcfc_fcfc_fcfc_fcfc,
];
const MATRIX_RESULT: [u64; 2] = [0x0000_0022_ffff_ffe9, 0xffff_ffc4_0000_0033];

fn decode(word: u32, thumb: bool) -> DecodedInsn {
    if thumb {
        ThumbDecoder::decode_32bit(word)
    } else {
        Aarch32Decoder::decode(word)
    }
    .unwrap()
}

fn operation(cpu: &mut Armv7Cpu, word: u32) -> ExecResult {
    let insn = decode(word, cpu.cpsr.t);
    Executor::new(cpu, &mut Memory32::new(4096, 0)).execute(&insn)
}

#[test]
fn int8_matrix_multiply_accumulate_executes_only_with_i8mm() {
    for thumb in [false, true] {
        for enabled in [true, false] {
            let mut cpu = Armv7Cpu::new();
            cpu.cpsr.t = thumb;
            cpu.cp15.id_isar6 = u32::from(enabled) * I8MM;
            cpu.vfp.dregs[..6].copy_from_slice(&MATRIX_INPUT);
            let initial = cpu.vfp.dregs;
            let flags = cpu.vfp.fpscr.bits();
            let result = operation(&mut cpu, SMMLA);
            if enabled {
                assert!(
                    matches!(result, ExecResult::Continue),
                    "Thumb={thumb}: {result:?}"
                );
                assert_eq!(cpu.vfp.dregs[..2], MATRIX_RESULT);
                assert_eq!(cpu.vfp.dregs[2..], initial[2..]);
            } else {
                assert!(matches!(result, ExecResult::Undefined));
                assert_eq!(cpu.vfp.dregs, initial);
            }
            assert_eq!(cpu.vfp.fpscr.bits(), flags);
        }
    }
}

#[test]
fn i8mm_requires_integer_simd_and_defined_feature_level_before_access() {
    for thumb in [false, true] {
        for level in [0, 1, 2, 15] {
            for profile in 0..4 {
                let mut cpu = hyp();
                cpu.cpsr.t = thumb;
                cpu.cp15.id_isar6 = level << 24;
                match profile {
                    1 => cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !15) | 1,
                    2 => cpu.vfp.mvfr1 &= !(15 << 12),
                    3 => cpu.vfp.mvfr1 &= !(0xff << 16),
                    _ => (),
                }
                let enabled = level == 1 && matches!(profile, 0 | 3);
                assert!(matches!(operation(&mut cpu, ISAR6), ExecResult::Continue));
                assert_eq!(cpu.regs[0] & (15 << 24), if enabled { I8MM } else { 0 });
                assert_eq!(cpu.cp15.id_isar6, level << 24);
                cpu.cp15.hcptr |= 1 << 10;
                let registers = cpu.vfp.dregs;
                let fpscr = cpu.vfp.fpscr.bits();
                for word in [SMMLA, USDOT, SUDOT_INDEXED] {
                    let result = operation(&mut cpu, word);
                    assert!(
                        if enabled {
                            matches!(result, ExecResult::FpAccessTrap { target_el: 2, .. })
                        } else {
                            matches!(result, ExecResult::Undefined)
                        },
                        "{word:08x} Thumb={thumb}, I8MM={level}, profile={profile}: {result:?}"
                    );
                    assert_eq!(cpu.vfp.dregs, registers);
                    assert_eq!(cpu.vfp.fpscr.bits(), fpscr);
                }
            }
        }
    }
}

#[test]
fn i8mm_reserved_encodings_and_thumb_it_policy() {
    for (word, rejected_bits) in [(SMMLA, 1), (USDOT, 1), (SUDOT_INDEXED, 0)] {
        for thumb in [false, true] {
            for bit in [1 << 12, 1 << 16, rejected_bits]
                .into_iter()
                .filter(|&bit| bit != 0)
            {
                assert_eq!(decode(word | bit, thumb).mnemonic, Mnemonic::UNDEFINED);
            }
            assert_eq!(
                decode(SMMLA | (1 << 23) | (1 << 4), thumb).mnemonic,
                Mnemonic::UNDEFINED
            );
            assert_eq!(decode(SUDOT_INDEXED | 1, thumb).mnemonic, Mnemonic::VSUDOT);
        }
        for predicate in [false, true] {
            let mut cpu = hyp();
            cpu.cpsr.t = true;
            cpu.cpsr.set_it_state(0, 8);
            cpu.cpsr.z = predicate;
            cpu.cp15.id_isar6 |= I8MM;
            cpu.cp15.hcptr |= 1 << 10;
            let registers = cpu.vfp.dregs;
            let exit = operation(&mut cpu, word);
            assert!(
                if predicate {
                    matches!(exit, ExecResult::Undefined)
                } else {
                    matches!(exit, ExecResult::Continue)
                },
                "{word:08x} Z={predicate}: {exit:?}"
            );
            assert_eq!(cpu.vfp.dregs, registers);
        }
    }
}

#[test]
fn mixed_i8mm_opt_in_matches_id_and_execution_after_state_import() {
    let id = Aarch64SysRegEncoding::new(3, 0, 0, 2, 7);
    for thumb in [false, true] {
        for (a64_enabled, a32_level) in [
            (true, None),
            (true, Some(1)),
            (false, Some(1)),
            (true, Some(2)),
        ] {
            let mut cpu = mixed(ISAR6, thumb, 2, false, true);
            let mut state = cpu.export_sregs();
            let execution = state.execution.as_mut().unwrap();
            let mut features = ArmFeatures::from_bits_retain(execution.features);
            features.set(ArmFeatures::I8MM, a64_enabled);
            execution.features = features.bits();
            let sys = &mut execution.sysregs;
            sys.id_aa64isar1_el1 =
                (sys.id_aa64isar1_el1 & !(15 << 52)) | (u64::from(a64_enabled) << 52);
            if let Some(level) = a32_level {
                sys.impl_defined.insert(id.encode(), level << 24);
            }
            sys.impl_defined
                .remove(&Aarch64SysRegEncoding::new(3, 4, 1, 1, 2).encode());
            let enabled = a64_enabled && a32_level == Some(1);
            let reported = u64::from(enabled) << 24;
            assert_eq!(sys.read(id, 1).unwrap() & (15 << 24), reported);
            let pfr = sys.id_aa64pfr0_el1;
            sys.id_aa64pfr0_el1 = (pfr & !15) | 1;
            assert_eq!(sys.read(id, 1).unwrap() & (15 << 24), 0);
            sys.id_aa64pfr0_el1 = pfr;
            cpu.import_sregs(&state).unwrap();
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(cpu.get_gpr(0) & (15 << 24), reported);

            let word = if thumb { SMMLA.rotate_left(16) } else { SMMLA };
            cpu.write_memory(0x104, &word.to_le_bytes()).unwrap();
            let vector = |lanes: &[u64]| u128::from(lanes[0]) | (u128::from(lanes[1]) << 64);
            for (index, operands) in (0u8..).zip(MATRIX_INPUT.chunks_exact(2)) {
                cpu.set_simd(index, vector(operands));
            }
            if enabled {
                assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
                assert_eq!(cpu.get_simd(0), vector(&MATRIX_RESULT));
                assert_eq!(cpu.instruction_count(), 2);
            } else {
                assert!(matches!(
                    cpu.step(),
                    Err(ArmError::UndefinedInstruction(SMMLA))
                ));
                assert_eq!(cpu.get_simd(0), vector(&MATRIX_INPUT[..2]));
                assert_eq!(cpu.instruction_count(), 1);
                assert_eq!(cpu.get_pc(), 0x104);
            }
        }
    }
}

#[test]
fn signed_unsigned_and_mixed_int8_products_match_qemu() {
    const REGISTERS: [usize; 8] = [0, 1, 2, 3, 4, 5, 20, 21];
    const INPUT: [u64; 8] = [
        0x7fff_fff8_ffff_fff0,
        0x8000_0001_ffff_fffe,
        0x8180_7fff_0403_0201,
        0x00fe_807e_eb97_8704,
        0x017f_80ff_8001_8001,
        0xfffe_01ff_fd80_a580,
        0xec0c_83ff_aca0_807f,
        0x9ffe_fca5_fb11_7f80,
    ];
    const FPSCR: u32 = 0xf8c0_0010;
    let fixture = include_str!("i8mm-qemu.tsv");
    assert_eq!(fixture.lines().count(), 33);
    for row in fixture.lines().skip(1) {
        let fields = row.split('\t').collect::<Vec<_>>();
        assert_eq!(fields.len(), 10);
        let word = u32::from_str_radix(fields[0], 16).unwrap();
        let assembly = fields[9];
        for thumb in [false, true] {
            let mut cpu = Armv7Cpu::new();
            cpu.cpsr.t = thumb;
            cpu.cpsr.n = true;
            cpu.cpsr.c = true;
            cpu.vfp.fpscr = Fpscr::from_bits(FPSCR);
            cpu.vfp.dregs.fill(0x55aa_55aa_55aa_55aa);
            for (reg, value) in REGISTERS.into_iter().zip(INPUT) {
                cpu.vfp.dregs[reg] = value;
            }
            let before = cpu.vfp.dregs;
            let cpsr = cpu.cpsr.to_u32();
            let exit = operation(&mut cpu, word);
            assert!(
                matches!(exit, ExecResult::Undefined),
                "{assembly} Thumb={thumb}: {exit:?}"
            );
            assert_eq!(cpu.vfp.dregs, before, "{assembly} Thumb={thumb}");
            assert_eq!(cpu.vfp.fpscr.bits(), FPSCR);
            assert_eq!(cpu.cpsr.to_u32(), cpsr);

            cpu.cp15.id_isar6 |= I8MM;
            let mut expected = before;
            for (reg, value) in REGISTERS.into_iter().zip(&fields[1..9]) {
                expected[reg] = u64::from_str_radix(value, 16).unwrap();
            }
            let exit = operation(&mut cpu, word);
            assert!(
                matches!(exit, ExecResult::Continue),
                "{assembly} Thumb={thumb}: {exit:?}"
            );
            assert_eq!(cpu.vfp.dregs, expected, "{assembly} Thumb={thumb}");
            assert_eq!(cpu.vfp.fpscr.bits(), FPSCR);
            assert_eq!(cpu.cpsr.to_u32(), cpsr);
        }
    }
}

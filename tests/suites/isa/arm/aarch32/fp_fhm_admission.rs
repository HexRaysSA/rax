//! FHM capability/admission cases matched to the retained QEMU profile matrix.
use super::*;

const WORDS: [u32; 8] = [
    0xfc22_0813,
    0xfc22_0853,
    0xfca2_0813,
    0xfca2_0853,
    0xfe02_0813,
    0xfe02_0853,
    0xfe12_0813,
    0xfe12_0853,
];
fn bytes(word: u32, thumb: bool) -> [u8; 4] {
    if thumb {
        word.rotate_left(16).to_le_bytes()
    } else {
        word.to_le_bytes()
    }
}
fn profile(word: u32, thumb: bool, fp16: bool, fhm: bool, trap: bool) -> AArch64Cpu {
    let mut cpu = mixed(bytes(word, thumb), thumb, fp16, trap);
    let mut state = cpu.export_sregs();
    let execution = state.execution.as_mut().unwrap();
    let mut features = ArmFeatures::from_bits(execution.features).unwrap();
    features.set(ArmFeatures::FHM, fhm);
    execution.features = features.bits();
    cpu.import_sregs(&state).unwrap();
    cpu
}
#[test]
fn mixed_fhm_requires_its_own_feature_and_fp16_before_access_traps() {
    let mut cases = 0;
    for fp16 in [false, true] {
        for fhm in [false, true] {
            for trap in [false, true] {
                for thumb in [false, true] {
                    for word in WORDS {
                        let mut cpu = profile(word, thumb, fp16, fhm, trap);
                        if !fp16 || !fhm {
                            rejected(&mut cpu);
                        } else if trap {
                            let before: Vec<_> = (0..32).map(|r| cpu.get_simd(r)).collect();
                            assert!(matches!(
                                cpu.step(),
                                Err(ArmError::ArchitecturalException {
                                    ec: 7,
                                    target_el: Some(3),
                                    ..
                                })
                            ));
                            assert_eq!(cpu.get_pc(), 0x100);
                            assert_eq!(cpu.instruction_count(), 0);
                            assert_eq!(
                                (0..32).map(|r| cpu.get_simd(r)).collect::<Vec<_>>(),
                                before
                            );
                        } else {
                            assert_eq!(
                                cpu.step().unwrap(),
                                CpuExit::Continue,
                                "{word:08x} T={thumb}"
                            );
                            assert_eq!(cpu.get_pc(), 0x104);
                            assert_eq!(cpu.instruction_count(), 1);
                        }
                        cases += 1;
                    }
                }
            }
        }
    }
    assert_eq!(cases, 128);
}
#[test]
fn standalone_fhm_field_and_vector_half_dependency_reject_reserved_profiles() {
    let mut cases = 0;
    for fhm in 0..16 {
        for simd in 0..4 {
            for thumb in [false, true] {
                for word in WORDS {
                    let insn = if thumb {
                        ThumbDecoder::decode_32bit(word)
                    } else {
                        Aarch32Decoder::decode(word)
                    }
                    .unwrap();
                    let mut cpu = Armv7Cpu::new();
                    cpu.cpsr.t = thumb;
                    cpu.cp15.id_isar6 = fhm << 8;
                    cpu.vfp.mvfr1 = (cpu.vfp.mvfr1 & !(15 << 20)) | (simd << 20);
                    cpu.vfp.dregs.fill(0x3c003c00_3c003c00);
                    let before = cpu.vfp.dregs;
                    let fpscr = cpu.vfp.fpscr.bits();
                    let mut mem = rax::isa::arm::execution::FlatMemory::new(4096, 0);
                    let id_read = if thumb {
                        ThumbDecoder::decode_32bit(0xee10_0ff2)
                    } else {
                        Aarch32Decoder::decode(0xee10_0ff2)
                    }
                    .unwrap();
                    assert!(matches!(
                        Executor::new(&mut cpu, &mut mem).execute(&id_read),
                        ExecResult::Continue
                    ));
                    assert_eq!((cpu.regs[0] >> 8) & 15, u32::from(fhm == 1 && simd == 2));
                    assert_eq!(cpu.cp15.id_isar6, fhm << 8);
                    let result = Executor::new(&mut cpu, &mut mem).execute(&insn);
                    if fhm == 1 && simd == 2 {
                        assert!(matches!(result, ExecResult::Continue));
                    } else {
                        assert!(
                            matches!(result, ExecResult::Undefined),
                            "FHM={fhm} SIMDHP={simd} {word:08x}: {result:?}"
                        );
                        assert_eq!(cpu.vfp.dregs, before);
                        assert_eq!(cpu.vfp.fpscr.bits(), fpscr);
                    }
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 1024);
}
#[test]
fn mixed_guest_fhm_id_and_a64_fields_follow_effective_capabilities() {
    for fp16 in [false, true] {
        for fhm in [false, true] {
            for thumb in [false, true] {
                let mut cpu = profile(0xee10_0ff2, thumb, fp16, fhm, false);
                assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
                let expected = u64::from(fp16 && fhm);
                assert_eq!(cpu.get_x(0), expected << 8);
                let state = cpu.export_sregs();
                let sys = &state.execution.as_ref().unwrap().sysregs;
                assert_eq!((sys.id_aa64isar0_el1 >> 48) & 15, expected);
                assert_eq!((sys.id_aa64pfr0_el1 >> 16) & 15, u64::from(fp16));
                assert_eq!((sys.id_aa64pfr0_el1 >> 20) & 15, u64::from(fp16));
            }
        }
    }
}

#[test]
fn fhm_id_follows_advsimd_dependencies_in_guest_reads_and_execution() {
    const MRC_ID_ISAR6: u32 = 0xee10_0ff2;
    const MRS_ID_ISAR6_EL1: u32 = 0xd538_02e0;
    const MRS_ID_AA64ISAR0_EL1: u32 = 0xd538_0600;
    let [mvfr0, mvfr1] = {
        let cpu = Armv7Cpu::new();
        [cpu.vfp.mvfr0, cpu.vfp.mvfr1]
    };

    for (test_mvfr0, test_mvfr1, implemented) in [
        (mvfr0, mvfr1, true),
        (mvfr0, (mvfr1 & !(15 << 20)) | (1 << 20), false),
        (mvfr0, (mvfr1 & !(15 << 20)) | (3 << 20), false),
        ((mvfr0 & !15) | 1, mvfr1, false),
        (mvfr0, mvfr1 & !(15 << 16), false),
        (mvfr0, mvfr1 & !(15 << 12), false),
    ] {
        for thumb in [false, true] {
            let expected = u64::from(implemented);
            let mut standalone = Armv7Cpu::new();
            standalone.cpsr.t = thumb;
            standalone.vfp.mvfr0 = test_mvfr0;
            standalone.vfp.mvfr1 = test_mvfr1;
            let id_read = if thumb {
                ThumbDecoder::decode_32bit(MRC_ID_ISAR6)
            } else {
                Aarch32Decoder::decode(MRC_ID_ISAR6)
            }
            .unwrap();
            let mut mem = rax::isa::arm::execution::FlatMemory::new(4096, 0);
            assert!(matches!(
                Executor::new(&mut standalone, &mut mem).execute(&id_read),
                ExecResult::Continue
            ));
            assert_eq!(u64::from(standalone.regs[0] >> 8) & 15, expected);

            let mut cpu = profile(WORDS[0], thumb, true, true, false);
            let mut state = cpu.export_sregs();
            let sys = &mut state.execution.as_mut().unwrap().sysregs;
            for (index, value) in [test_mvfr0, test_mvfr1].into_iter().enumerate() {
                sys.impl_defined.insert(
                    Aarch64SysRegEncoding::new(3, 0, 0, 3, index as u8).encode(),
                    u64::from(value),
                );
            }
            cpu.import_sregs(&state).unwrap();
            cpu.set_pstate_bits(0x3cd).unwrap();
            cpu.set_pc(0x200);
            cpu.write_memory(0x200, &MRS_ID_ISAR6_EL1.to_le_bytes())
                .unwrap();
            cpu.write_memory(0x204, &MRS_ID_AA64ISAR0_EL1.to_le_bytes())
                .unwrap();
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!((cpu.get_x(0) >> 8) & 15, expected);
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!((cpu.get_x(0) >> 48) & 15, 1);

            cpu.set_pstate_bits(0x1d3 | if thumb { 32 } else { 0 })
                .unwrap();
            cpu.set_pc(0xfc);
            cpu.write_memory(0xfc, &bytes(MRC_ID_ISAR6, thumb)).unwrap();
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!((cpu.get_x(0) >> 8) & 15, expected);
            let result = cpu.step();
            assert_eq!(cpu.get_pc(), if implemented { 0x104 } else { 0x100 });
            if implemented {
                assert_eq!(result.unwrap(), CpuExit::Continue);
            } else {
                assert!(matches!(result, Err(ArmError::UndefinedInstruction(_))));
            }
        }
    }
}

use super::*;
use crate::isa::arm::common::memory::FlatMemory;

const WORDS: [u32; 16] = [
    0x0e22_ec20,
    0x4e22_ec20,
    0x0ea2_ec20,
    0x4ea2_ec20,
    0x2e22_cc20,
    0x6e22_cc20,
    0x2ea2_cc20,
    0x6ea2_cc20,
    0x0f82_0020,
    0x4f82_0020,
    0x0f82_4020,
    0x4f82_4020,
    0x2f82_8020,
    0x6f82_8020,
    0x2f82_c020,
    0x6f82_c020,
];
fn cpu(word: u32, fp16: bool, fhm: bool, trap: bool) -> AArch64Cpu {
    let mut config = AArch64Config::default();
    config.gic_config = None;
    config.features.set(ArmFeatures::FP16, fp16);
    config.features.set(ArmFeatures::FHM, fhm);
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 4096)));
    cpu.sysregs.el1.cpacr = if trap { 0 } else { 3 << 20 };
    cpu.pc = 0x100;
    cpu.write_memory(cpu.pc, &word.to_le_bytes()).unwrap();
    cpu.v.fill(0x3c003c00_3c003c00_3c003c00_3c003c00);
    cpu
}
#[test]
fn fhm_vector_and_indexed_decode_admission_precedes_access_and_retirement() {
    for fp16 in [false, true] {
        for fhm in [false, true] {
            for trap in [false, true] {
                for word in WORDS {
                    assert_eq!(fhm_encoding(word), Some(true), "{word:08x}");
                    let mut cpu = cpu(word, fp16, fhm, trap);
                    let before = cpu.v;
                    let result = cpu.step();
                    if !fp16 || !fhm {
                        assert!(matches!(result,Err(ArmError::UndefinedInstruction(w)) if w==word));
                        assert_eq!(cpu.pc, 0x100);
                        assert_eq!(cpu.insn_count, 0);
                        assert_eq!(cpu.cycle_count, 0);
                        assert_eq!(cpu.v, before);
                    } else if trap {
                        assert!(matches!(
                            result,
                            Err(ArmError::ArchitecturalException { ec: 7, iss: 0, .. })
                        ));
                        assert_eq!(cpu.pc, 0x100);
                        assert_eq!(cpu.insn_count, 0);
                        assert_eq!(cpu.cycle_count, 0);
                        assert_eq!(cpu.v, before);
                    } else {
                        assert_eq!(result.unwrap(), CpuExit::Continue);
                        assert_eq!(cpu.pc, 0x104);
                        assert_eq!(cpu.insn_count, 1);
                    }
                }
            }
        }
    }
}
#[test]
fn reserved_fhm_vector_size_is_undefined_even_with_fp_access_trapping() {
    for word in WORDS.into_iter().take(8) {
        let word = word | (1 << 22);
        let mut cpu = cpu(word, true, true, true);
        let before = cpu.v;
        assert_eq!(fhm_encoding(word), Some(false));
        assert!(matches!(cpu.step(),Err(ArmError::UndefinedInstruction(w)) if w==word));
        assert_eq!(cpu.pc, 0x100);
        assert_eq!(cpu.insn_count, 0);
        assert_eq!(cpu.v, before);
    }
}
#[test]
fn fhm_profile_ids_reset_and_aarch32_id_alias_are_consistent() {
    for fp16 in [false, true] {
        for fhm in [false, true] {
            let mut cpu = cpu(WORDS[0], fp16, fhm, false);
            for reset in [false, true] {
                if reset {
                    cpu.reset();
                }
                let expected = u64::from(fp16 && fhm);
                assert_eq!(
                    cpu.read_sysreg(Aarch64SysRegEncoding::new(3, 0, 0, 2, 7))
                        .unwrap(),
                    expected << 8
                );
                let encoding = Aarch64SysRegEncoding::new(3, 0, 0, 2, 7);
                assert_eq!(cpu.sysregs.read(encoding, 3), Some(expected << 8));
                let state = crate::vm::vcpu::Aarch64CpuState {
                    regs: crate::vm::vcpu::Aarch64Registers {
                        pstate: cpu.pstate_bits(),
                        ..Default::default()
                    },
                    sregs: cpu.export_sregs(),
                };
                let ir = crate::smir::ir::context::Aarch64RegState::from_cpu_state(&state).unwrap();
                assert_eq!(
                    ir.read_system_register(encoding.encode()),
                    Some(expected << 8)
                );
                assert_eq!((cpu.sysregs.id_aa64isar0_el1 >> 48) & 15, expected);
                assert_eq!((cpu.sysregs.id_aa64pfr0_el1 >> 16) & 15, u64::from(fp16));
                assert_eq!((cpu.sysregs.id_aa64pfr0_el1 >> 20) & 15, u64::from(fp16));
            }
        }
    }
    assert!(!ArmFeatures::armv8_2_base().contains(ArmFeatures::FHM));
    assert!(ArmFeatures::armv8_4_base().contains(ArmFeatures::FP16 | ArmFeatures::FHM));
}
#[test]
fn reserved_top_bit_in_both_fhm_classes_is_undefined_before_access_traps() {
    for word in WORDS {
        let word = word | (1 << 31);
        let mut cpu = cpu(word, true, true, true);
        assert_eq!(fhm_encoding(word), Some(false));
        assert!(matches!(cpu.step(), Err(ArmError::UndefinedInstruction(w)) if w == word));
        assert_eq!(cpu.pc, 0x100);
        assert_eq!(cpu.insn_count, 0);
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn unsupported_native_fhm_resumes_at_the_exact_interpreter_frontier() {
    // The stateless lifter has no FHM implementation. Do not promote it merely
    // because the direct CPU supports the selected profile. A preceding ADD
    // must retire once, and a denied FHM must leave the precise fault PC.
    for fp16 in [false, true] {
        for fhm in [false, true] {
            for word in WORDS {
                let mut cpu = cpu(word, fp16, fhm, false);
                let code = [0x91000400, word, 0xd4200000]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect::<Vec<_>>();
                cpu.write_memory(0x100, &code).unwrap();
                assert!(
                    cpu.jit_compile_region().is_none(),
                    "unsupported FHM {word:08x}"
                );
                assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
                assert_eq!(cpu.x[0], 1);
                assert_eq!(cpu.pc, 0x104);
                let result = cpu.step();
                if fp16 && fhm {
                    assert_eq!(result.unwrap(), CpuExit::Continue);
                    assert_eq!(cpu.pc, 0x108);
                    assert_eq!(cpu.insn_count, 2);
                } else {
                    assert!(matches!(result, Err(ArmError::UndefinedInstruction(w)) if w == word));
                    assert_eq!(cpu.pc, 0x104);
                    assert_eq!(cpu.insn_count, 1);
                }
                assert_eq!(cpu.x[0], 1);
            }
        }
    }
}

#[test]
fn illegal_execution_state_precedes_fhm_capability_and_access_rejection() {
    for fp16 in [false, true] {
        for fhm in [false, true] {
            for el in [0u8, 1] {
                for word in WORDS {
                    for instruction in [word, word | (1 << 31)] {
                        let mut cpu = cpu(instruction, fp16, fhm, true);
                        let pstate = (u64::from(el) << 2) | u64::from(el != 0) | (1 << 20);
                        cpu.set_pstate_bits(pstate).unwrap();
                        let before = cpu.v;
                        assert!(matches!(
                            cpu.step(),
                            Err(ArmError::ArchitecturalException {
                                ec: 0x0e,
                                iss: 0,
                                target_el: Some(1)
                            })
                        ));
                        assert_eq!(cpu.pc, 0x100);
                        assert_eq!(cpu.insn_count, 0);
                        assert_eq!(cpu.v, before);
                        assert!(cpu.il);
                    }
                }
            }
        }
    }
}

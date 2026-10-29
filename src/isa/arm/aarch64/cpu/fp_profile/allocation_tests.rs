//! Independent allocation and precise-fault checks for the FP/SIMD namespace.
use super::*;
use crate::isa::arm::common::memory::FlatMemory;

const ENTRY: u64 = 0x1000;

fn corpus() -> Vec<(u32, bool)> {
    let data: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a64-fpsimd-allocation/oracle-corpus.json"
    )))
    .unwrap();
    data["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["word"].as_u64().unwrap() as u32,
                row["expected"].as_str().unwrap() == "D",
            )
        })
        .collect()
}

fn cpu(el: u8, fpen: u64) -> AArch64Cpu {
    let mut config = AArch64Config {
        initial_el: el,
        gic_config: None,
        ..Default::default()
    };
    config.features |= SELECTABLE_FEATURES;
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x8000)));
    cpu.pc = ENTRY;
    cpu.sysregs.el1.cpacr = fpen << 20;
    cpu.sysregs.el1.vbar = 0x2000;
    cpu.x = std::array::from_fn(|i| 0x1234_0000_0000_0000 | i as u64);
    cpu.v = std::array::from_fn(|i| (i as u128) << 96 | 0x7fc0_dead);
    cpu.fpcr = 0x0400_0000;
    cpu.fpsr = 0x0800_0011;
    cpu.insn_count = 17;
    cpu.cycle_count = 29;
    cpu.btype = 2;
    cpu.execution.disabled = true;
    cpu
}

#[test]
fn independent_allocated_and_reserved_words_precede_fp_permission_checks() {
    let words = corpus();
    assert_eq!(words.len(), 26978);
    let mut failures = Vec::new();
    for el in [0, 1] {
        let mut cpu = cpu(el, 0);
        for &(word, allocated) in &words {
            cpu.write_memory(ENTRY, &word.to_le_bytes()).unwrap();
            let before = CoreCheckpoint::capture(&cpu).unwrap();
            let result = cpu.step();
            let correct = if allocated {
                matches!(result, Err(ArmError::ArchitecturalException { ec: 7, .. }))
            } else {
                result == Err(ArmError::UndefinedInstruction(word))
            };
            if !correct || CoreCheckpoint::capture(&cpu).unwrap() != before {
                failures.push(format!(
                    "{word:08x} EL{el}, allocated={allocated}: {result:?}"
                ));
            }
            // Keep every independent counterexample visible without allowing a
            // failed retirement to alter the initial state of the next case.
            before.install_in_prepared(&mut cpu).unwrap();
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures: {failures:?}",
        failures.len()
    );
}

#[test]
fn independent_reserved_words_retry_at_saturated_counters_then_replace_once() {
    for el in [0, 1] {
        let mut cpu = cpu(el, 3);
        for (word, allocated) in corpus() {
            if allocated {
                continue;
            }
            cpu.pc = ENTRY;
            cpu.btype = 2;
            cpu.insn_count = u64::MAX;
            cpu.cycle_count = u64::MAX;
            cpu.write_memory(ENTRY, &word.to_le_bytes()).unwrap();
            let before = CoreCheckpoint::capture(&cpu).unwrap();
            for _ in 0..2 {
                assert_eq!(
                    cpu.step(),
                    Err(ArmError::UndefinedInstruction(word)),
                    "{word:08x}"
                );
                assert_eq!(CoreCheckpoint::capture(&cpu).unwrap(), before, "{word:08x}");
            }
            cpu.insn_count = 17;
            cpu.cycle_count = 29;
            let value = cpu.x[9];
            cpu.write_memory(ENTRY, &0x9100_0529u32.to_le_bytes())
                .unwrap();
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(
                (cpu.pc, cpu.insn_count, cpu.cycle_count, cpu.btype),
                (ENTRY + 4, 18, 30, 0)
            );
            assert_eq!(cpu.x[9], value + 1);
        }
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn native_requirements_reject_reserved_original_words_before_optimization() {
    use crate::smir::ir::ops::{OpKind, SmirOp};
    use crate::smir::ir::types::{BlockId, FunctionId, OpId};
    use crate::smir::ir::{SmirBlock, SmirFunction};
    // A no-op may disappear under optimization. Admission must still observe
    // the original word before the optimizer removes its source-PC carrier.
    let mut function = SmirFunction::new(FunctionId(0), BlockId(0), ENTRY);
    let mut block = SmirBlock::new(BlockId(0), ENTRY);
    block.push_op(SmirOp::new(OpId(0), ENTRY, OpKind::Nop));
    function.add_block(block);
    let cpu = cpu(1, 3);
    let mut failures = Vec::new();
    for (word, allocated) in corpus() {
        let result = cpu.native_requirements(&function, ENTRY, &word.to_le_bytes());
        if result.is_some() != allocated {
            failures.push(format!("{word:08x}, allocated={allocated}: {result:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures: {failures:?}",
        failures.len()
    );
}

#[test]
fn newer_unrepresented_words_remain_undefined_in_the_selected_base_profile() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a64-fpsimd-allocation/newer-profile-boundaries.json"
    )))
    .unwrap();
    assert_eq!(corpus["words"].as_array().unwrap().len(), 22);
    for el in [0, 1] {
        let mut cpu = cpu(el, 0);
        for word in corpus["words"].as_array().unwrap() {
            let word = word.as_u64().unwrap() as u32;
            cpu.write_memory(ENTRY, &word.to_le_bytes()).unwrap();
            let before = CoreCheckpoint::capture(&cpu).unwrap();
            assert_eq!(
                cpu.step(),
                Err(ArmError::UndefinedInstruction(word)),
                "{word:08x}"
            );
            assert_eq!(CoreCheckpoint::capture(&cpu).unwrap(), before);
        }
    }
}

#[test]
fn existing_fp8_version_policy_precedes_fp_access_for_all_operand_boundaries() {
    for version in [ArmVersion::V9_3A, ArmVersion::V9_4A] {
        for el in [0, 1] {
            for fpen in [0, 3] {
                let mut cpu = cpu(el, fpen);
                cpu.config.version = version;
                // These are admission/control checks. General FP8 arithmetic,
                // source format, scaling and FPMR semantics need separate proof.
                cpu.v.fill(0);
                for top in [0, 1] {
                    for rm in [0, 7] {
                        for index in [0, 15] {
                            for rn in [0, 31] {
                                for rd in [0, 31] {
                                    let word: u32 = 0x0fc0_0000
                                        | (top << 30)
                                        | (rm << 16)
                                        | ((index & 1) << 19)
                                        | (((index >> 1) & 1) << 20)
                                        | (((index >> 2) & 1) << 21)
                                        | (((index >> 3) & 1) << 11)
                                        | (rn << 5)
                                        | rd;
                                    cpu.pc = ENTRY;
                                    cpu.btype = 2;
                                    cpu.write_memory(ENTRY, &word.to_le_bytes()).unwrap();
                                    let count = cpu.insn_count;
                                    let before = CoreCheckpoint::capture(&cpu).unwrap();
                                    let result = cpu.step();
                                    if version < ArmVersion::V9_4A {
                                        assert_eq!(
                                            result,
                                            Err(ArmError::UndefinedInstruction(word))
                                        );
                                    } else if fpen == 0 {
                                        assert!(matches!(
                                            result,
                                            Err(ArmError::ArchitecturalException { ec: 7, .. })
                                        ));
                                    } else {
                                        assert_eq!(
                                            result.unwrap(),
                                            CpuExit::Continue,
                                            "{word:08x}"
                                        );
                                        assert_eq!(cpu.insn_count, count + 1);
                                        continue;
                                    }
                                    assert_eq!(CoreCheckpoint::capture(&cpu).unwrap(), before);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn native_fp8_original_word_obeys_the_existing_version_policy() {
    use crate::smir::ir::ops::{OpKind, SmirOp};
    use crate::smir::ir::types::{BlockId, FunctionId, OpId};
    use crate::smir::ir::{SmirBlock, SmirFunction};
    let mut function = SmirFunction::new(FunctionId(0), BlockId(0), ENTRY);
    let mut block = SmirBlock::new(BlockId(0), ENTRY);
    block.push_op(SmirOp::new(OpId(0), ENTRY, OpKind::Nop));
    function.add_block(block);
    for version in [ArmVersion::V9_3A, ArmVersion::V9_4A] {
        let mut cpu = cpu(1, 3);
        cpu.config.version = version;
        for word in [0x0fc0_0000u32, 0x4fc0_0000, 0x0ff8_0bff, 0x4ff8_0bff] {
            let before = CoreCheckpoint::capture(&cpu).unwrap();
            let admitted = cpu.native_requirements(&function, ENTRY, &word.to_le_bytes());
            assert_eq!(
                admitted.is_some(),
                version >= ArmVersion::V9_4A,
                "{word:08x}"
            );
            assert_eq!(CoreCheckpoint::capture(&cpu).unwrap(), before);
        }
    }
}

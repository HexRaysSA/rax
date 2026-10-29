use super::*;
use crate::isa::arm::common::memory::FlatMemory;

fn configured(word: u32, fp16: bool) -> AArch64Cpu {
    let mut config = AArch64Config::default();
    config.gic_config = None;
    config.features.set(ArmFeatures::FP16, fp16);
    config.features.remove(ArmFeatures::FHM);
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x5000)));
    cpu.pc = 0x1000;
    cpu.sysregs.el1.cpacr = 3 << 20;
    cpu.v[1] = 0x3c00;
    cpu.v[2] = 0x3c00;
    cpu.write_memory(cpu.pc, &word.to_le_bytes()).unwrap();
    cpu
}

#[test]
fn half_absence_rejects_original_arithmetic_before_retirement() {
    let word = 0x1ee2_2820;
    let mut cpu = configured(word, false);
    let before = (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.pstate_bits());
    let result = cpu.step();
    eprintln!(
        "fp16=false result={result:?} pc={:#x} retired={} h0={:#x}",
        cpu.pc, cpu.insn_count, cpu.v[0]
    );
    assert!(matches!(result, Err(ArmError::UndefinedInstruction(w)) if w == word));
    assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (0x1000, 0, 0));
    assert_eq!(
        (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.pstate_bits()),
        before
    );
}

#[test]
fn half_absence_precedes_access_for_all_encoding_classes_and_registers() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a64-half-admission/encodings.json"
    )))
    .unwrap();
    for case in corpus["records"].as_array().unwrap() {
        let mask = case["mask"].as_u64().unwrap() as u32;
        let value = case["value"].as_u64().unwrap() as u32;
        for register in 0..32u32 {
            let fields = register | ((31 - register) << 5) | ((register ^ 16) << 16);
            let word = value | (fields & !mask);
            for el in [0, 1] {
                for fpen in [0, 3] {
                    let mut cpu = configured(word, false);
                    cpu.current_el = el;
                    cpu.sp_sel = el != 0;
                    cpu.sysregs.el1.cpacr = fpen << 20;
                    if register == 31 {
                        cpu.insn_count = u64::MAX;
                        cpu.cycle_count = u64::MAX;
                    }
                    let before = (
                        cpu.x,
                        cpu.v,
                        cpu.fpcr,
                        cpu.fpsr,
                        cpu.pstate_bits(),
                        cpu.insn_count,
                        cpu.cycle_count,
                    );
                    assert!(
                        matches!(cpu.step(), Err(ArmError::UndefinedInstruction(w)) if w == word),
                        "{word:08x} EL{el} FPEN{fpen}"
                    );
                    assert_eq!(cpu.pc, 0x1000);
                    assert_eq!(
                        (
                            cpu.x,
                            cpu.v,
                            cpu.fpcr,
                            cpu.fpsr,
                            cpu.pstate_bits(),
                            cpu.insn_count,
                            cpu.cycle_count
                        ),
                        before
                    );
                }
            }
        }
    }
}

#[test]
fn half_illegal_execution_state_precedes_feature_and_access_rejection() {
    for present in [false, true] {
        let mut cpu = configured(0x1ee2_2820, present);
        cpu.il = true;
        cpu.sysregs.el1.cpacr = 0;
        let before = cpu.v;
        assert!(matches!(
            cpu.step(),
            Err(ArmError::ArchitecturalException { ec: 0x0e, .. })
        ));
        assert_eq!((cpu.pc, cpu.insn_count, cpu.v), (0x1000, 0, before));
    }
}

#[test]
fn half_reserved_fields_precede_access_even_when_fp16_is_present() {
    // Independent EL0/EL1 Cortex-A76 guests report EC=0 for these words,
    // including when CPACR_EL1.FPEN=0. The last word requires FEAT_FPRCVT,
    // which this profile does not implement.
    for word in [0x1ec2_0020, 0x1eca_0020, 0x1eea_0020] {
        assert_eq!(instruction_features(word), None, "{word:08x}");
        for present in [false, true] {
            for el in [0, 1] {
                for fpen in [0, 3] {
                    let mut cpu = configured(word, present);
                    cpu.current_el = el;
                    cpu.sp_sel = el != 0;
                    cpu.sysregs.el1.cpacr = fpen << 20;
                    let before = (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.pstate_bits());
                    assert!(
                        matches!(cpu.step(), Err(ArmError::UndefinedInstruction(w)) if w == word),
                        "{word:08x} FP16={present} EL{el} FPEN={fpen}"
                    );
                    assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (0x1000, 0, 0));
                    assert_eq!(
                        (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.pstate_bits()),
                        before
                    );
                }
            }
        }
    }
}

#[test]
fn half_and_full_reduction_reserved_fields_precede_access() {
    let mut reserved = vec![0x7eb0_d820, 0x7ef0_d820];
    for base in [0x2e30_c820, 0x2e30_d820, 0x2e30_f820] {
        for q in [0, 1] {
            for size in 0..4 {
                let word = base | (q << 30) | (size << 22);
                if q == 0 || size & 1 != 0 || base == 0x2e30_d820 {
                    reserved.push(word);
                }
            }
        }
    }
    assert_eq!(reserved.len(), 22);
    for word in reserved {
        assert_eq!(instruction_features(word), None, "{word:08x}");
        for present in [false, true] {
            for fpen in [0, 3] {
                let mut cpu = configured(word, present);
                cpu.sysregs.el1.cpacr = fpen << 20;
                let before = (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr);
                assert!(
                    matches!(cpu.step(), Err(ArmError::UndefinedInstruction(w)) if w == word),
                    "{word:08x} FP16={present} FPEN={fpen}"
                );
                assert_eq!((cpu.pc, cpu.insn_count), (0x1000, 0));
                assert_eq!((cpu.x, cpu.v, cpu.fpcr, cpu.fpsr), before);
            }
        }
    }
    for word in [
        0x6e30_c820,
        0x6eb0_c820,
        0x6e30_f820,
        0x6eb0_f820,
        0x7e30_d820,
        0x7e70_d820,
    ] {
        let mut cpu = configured(word, false);
        assert_eq!(instruction_features(word), Some(ArmFeatures::empty()));
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue, "{word:08x}");
        assert_eq!((cpu.pc, cpu.insn_count), (0x1004, 1));
    }
}

#[test]
fn half_legacy_conversion_storage_and_integer_vectors_need_no_fp16_arithmetic() {
    for word in [
        0x1e23_c020u32,
        0x1ee2_4020,
        0x1e63_c020,
        0x1ee2_c020,
        0x0e21_6820,
        0x0e21_7820,
        0x7d40_0000,
        0x7d00_0001,
        0x0f00_8420,
        0x0e02_0c20,
    ] {
        assert_eq!(
            instruction_features(word),
            Some(ArmFeatures::empty()),
            "{word:08x}"
        );
        for denied in [false, true] {
            let mut cpu = configured(word, false);
            cpu.x[0] = 0x2000;
            cpu.sysregs.el1.cpacr = if denied { 0 } else { 3 << 20 };
            let result = cpu.step();
            if denied {
                assert!(
                    matches!(result, Err(ArmError::ArchitecturalException { ec: 7, .. })),
                    "{word:08x} {result:?}"
                );
                assert_eq!((cpu.pc, cpu.insn_count), (0x1000, 0));
            } else {
                assert_eq!(result.unwrap(), CpuExit::Continue, "{word:08x}");
                assert_eq!((cpu.pc, cpu.insn_count), (0x1004, 1));
            }
        }
    }
    assert_eq!(
        instruction_features(0xce42_0c20),
        Some(ArmFeatures::empty())
    );
    // BFCVT has an H destination but needs BF16, independently of FP16.
    assert_eq!(instruction_features(0x1e63_4020), Some(ArmFeatures::BF16));
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn half_native_feature_metadata_is_checked_at_entry_and_in_cache_keys() {
    use std::sync::Arc;
    let mut cpu = configured(0x9100_0400, true);
    let bytes = [0x9100_0400u32, 0xf100_081f, 0x54ff_ffc3, 0xd420_0000]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    cpu.write_memory(0x1000, &bytes).unwrap();
    let mut region = cpu.jit_compile_region().expect("integer native control");
    assert!(region.fp_features.is_empty());
    assert!(cpu.jit_run_region(&region));
    assert_eq!((cpu.pc, cpu.x[0]), (0x100c, 2));
    // Test the feature guard using real integer code and synthetic metadata.
    // This does not assert native execution support for an FP16 instruction.
    region.fp_features = ArmFeatures::FP16;
    let region = Arc::new(region);
    let enabled = cpu.jit_mode_tag();
    cpu.jit
        .cache
        .insert((0x1000, enabled), Some(region.clone()));
    cpu.config.features.remove(ArmFeatures::FP16);
    cpu.update_fp_id_registers();
    cpu.pc = 0x1000;
    cpu.x[0] = 0;
    let before = (cpu.pc, cpu.x, cpu.v, cpu.insn_count);
    assert!(!cpu.jit_run_region(&region));
    assert_eq!((cpu.pc, cpu.x, cpu.v, cpu.insn_count), before);
    let denied = cpu.jit_mode_tag();
    assert_ne!(denied, enabled);
    cpu.jit.cache.insert((0x1000, denied), Some(region.clone()));
    assert!(cpu.jit_lookup(0x1000).is_none());
    cpu.jit.cache.insert((0x1000, denied), None);
    cpu.config.features.insert(ArmFeatures::FP16);
    cpu.update_fp_id_registers();
    assert_eq!(cpu.jit_mode_tag(), enabled);
    assert!(Arc::ptr_eq(&cpu.jit_lookup(0x1000).unwrap(), &region));
    assert!(cpu.jit_run_region(&region));
    assert_eq!((cpu.pc, cpu.x[0]), (0x100c, 2));
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn half_native_admission_retains_original_feature_dependencies() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a64-half-admission/encodings.json"
    )))
    .unwrap();
    let mut admitted = Vec::new();
    for case in corpus["records"].as_array().unwrap() {
        let mask = case["mask"].as_u64().unwrap() as u32;
        let mut word = case["value"].as_u64().unwrap() as u32;
        word |= ((1 << 5) | (2 << 16)) & !mask;
        if case["name"]
            .as_str()
            .unwrap()
            .starts_with("aarch64_float_convert_")
        {
            word = (word & !31) | 9;
        }
        let mut cpu = configured(word, false);
        let code = [
            0x9100_0400,
            word,
            0x1e27_03e0,
            0xf100_081f,
            0x54ff_ff83,
            0xd420_0000,
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
        cpu.write_memory(0x1000, &code).unwrap();
        let compiled = cpu.jit_compile_region();
        eprintln!(
            "FP16 absent {word:08x}: native_admitted={} name={}",
            compiled.is_some(),
            case["name"]
        );
        if compiled.is_some() {
            admitted.push(word);
        }
    }
    assert!(
        admitted.is_empty(),
        "native admission with absent FP16: {admitted:x?}"
    );
}

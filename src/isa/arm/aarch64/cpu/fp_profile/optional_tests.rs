use super::*;
use crate::isa::arm::common::memory::FlatMemory;

const CASES: [(ArmFeatures, u32, bool, u32); 6] = [
    (ArmFeatures::JSCVT, 0x1e7e_0020, true, 12),
    (ArmFeatures::FCMA, 0x6e82_e420, true, 16),
    (ArmFeatures::FRINTTS, 0x1e28_4020, true, 32),
    (ArmFeatures::BF16, 0x1e63_4020, true, 44),
    (ArmFeatures::I8MM, 0x4e82_a420, true, 52),
    (ArmFeatures::DOTPROD, 0x4e82_9420, false, 44),
];

fn selected(bits: u8) -> ArmFeatures {
    CASES
        .iter()
        .enumerate()
        .fold(ArmFeatures::empty(), |flags, (i, &(feature, ..))| {
            flags
                | if bits & (1 << i) != 0 {
                    feature
                } else {
                    ArmFeatures::empty()
                }
        })
}

fn configured(bits: u8, word: u32) -> AArch64Cpu {
    let mut config = AArch64Config::default();
    config.gic_config = None;
    config.features.remove(optional::FEATURES);
    config.features |= selected(bits);
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x5000)));
    cpu.pc = 0x1000;
    cpu.sysregs.el1.cpacr = 3 << 20;
    cpu.x[0] = 0x55;
    cpu.v[1] = 7.5f64.to_bits() as u128;
    cpu.write_memory(cpu.pc, &word.to_le_bytes()).unwrap();
    cpu
}

#[test]
fn optional_feature_absence_precedes_fp_access_and_retirement() {
    for bits in 0..64 {
        for (feature, word, _, _) in CASES {
            for el in [0, 1] {
                for fpen in 0..4 {
                    let mut cpu = configured(bits, word);
                    cpu.current_el = el;
                    cpu.sp_sel = el != 0;
                    cpu.sysregs.el1.cpacr = fpen << 20;
                    let before = (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.pstate_bits());
                    let result = cpu.step();
                    let present = selected(bits).contains(feature);
                    if !present {
                        assert!(
                            matches!(result, Err(ArmError::UndefinedInstruction(w)) if w == word),
                            "{word:08x} flags={bits:02x} EL{el} FPEN={fpen}: {result:?}"
                        );
                    } else if fpen == 3 || (fpen == 1 && el == 1) {
                        assert_eq!(result.unwrap(), CpuExit::Continue, "{word:08x}");
                        assert_eq!((cpu.pc, cpu.insn_count), (0x1004, 1));
                        continue;
                    } else {
                        assert!(
                            matches!(result, Err(ArmError::ArchitecturalException { ec: 7, .. })),
                            "{word:08x}: {result:?}"
                        );
                    }
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
fn optional_ids_match_selected_flags_and_preserve_unowned_fields() {
    const OWNED0: u64 = 15 << 44;
    const OWNED1: u64 = (15 << 12) | (15 << 16) | (15 << 32) | (15 << 44) | (15 << 52);
    for bits in 0..64 {
        let mut cpu = configured(bits, 0xd503_201f);
        for (feature, _, isar1, shift) in CASES {
            let value = if isar1 {
                cpu.sysregs.id_aa64isar1_el1
            } else {
                cpu.sysregs.id_aa64isar0_el1
            };
            assert_eq!(
                (value >> shift) & 15,
                u64::from(selected(bits).contains(feature))
            );
        }
        cpu.validate_fp_profile().unwrap();
        let mut registers = cpu.sysregs.clone();
        registers.id_aa64isar0_el1 = 0xa5a5_f0f0_c3c3_9696;
        registers.id_aa64isar1_el1 = 0x5a5a_0f0f_3c3c_6969;
        optional::update_ids(&mut registers, selected(bits));
        assert_eq!(
            registers.id_aa64isar0_el1 & !OWNED0,
            0xa5a5_f0f0_c3c3_9696 & !OWNED0
        );
        assert_eq!(
            registers.id_aa64isar1_el1 & !OWNED1,
            0x5a5a_0f0f_3c3c_6969 & !OWNED1
        );
        cpu.sysregs.id_aa64isar1_el1 ^= 1 << 12;
        assert!(cpu.validate_fp_profile().is_err());
        cpu.reset();
        cpu.validate_fp_profile().unwrap();
    }
}

#[test]
fn optional_unsupported_host_id_levels_reject_before_mutation() {
    for (_, _, isar1, shift) in CASES {
        for value in 2..16 {
            let mut cpu = configured(0, 0xd503_201f);
            let before = cpu.export_sregs();
            let mut source = before.clone();
            let system = &mut source.execution.as_mut().unwrap().sysregs;
            let register = if isar1 {
                &mut system.id_aa64isar1_el1
            } else {
                &mut system.id_aa64isar0_el1
            };
            *register = (*register & !(15 << shift)) | (value << shift);
            assert!(cpu.import_sregs(&source).is_err());
            assert_eq!(cpu.export_sregs(), before);
        }
    }
}

#[test]
fn optional_reserved_controls_precede_access_in_enabled_profiles() {
    for word in [
        0x1ea8_4020,
        0x1ee8_4020,
        0x1e23_4020,
        0x1ea3_4020,
        0x1ee3_4020,
        0x0e61_e820,
        0x0ee1_6820,
        0x0e82_a420,
        0x6e82_ac20,
        0x2e42_ec20,
        0x6e02_ec20,
        0x6e02_e420,
        0x2ec2_e420,
        0x2f82_1020,
        0x6fa2_1020,
        0x2f42_1820,
        0x6fc2_1020,
    ] {
        assert_eq!(instruction_features(word), None, "{word:08x}");
        for fpen in [0, 3] {
            let mut cpu = configured(63, word);
            cpu.config.features.insert(ArmFeatures::FP16);
            cpu.update_fp_id_registers();
            cpu.sysregs.el1.cpacr = fpen << 20;
            assert!(
                matches!(cpu.step(), Err(ArmError::UndefinedInstruction(w)) if w == word),
                "{word:08x} FPEN={fpen}"
            );
            assert_eq!((cpu.pc, cpu.insn_count), (0x1000, 0));
        }
    }
}

#[test]
fn optional_complex_half_requires_both_independent_capabilities() {
    for word in [0x2e42_e420, 0x2e42_c420, 0x6f42_1020] {
        assert_eq!(
            instruction_features(word),
            Some(ArmFeatures::FCMA | ArmFeatures::FP16)
        );
        for complex in [false, true] {
            for half in [false, true] {
                let mut cpu = configured(if complex { 2 } else { 0 }, word);
                cpu.config.features.set(ArmFeatures::FP16, half);
                cpu.update_fp_id_registers();
                let result = cpu.step();
                if complex && half {
                    assert_eq!(result.unwrap(), CpuExit::Continue);
                } else {
                    assert!(matches!(result, Err(ArmError::UndefinedInstruction(w)) if w == word));
                    assert_eq!(cpu.insn_count, 0);
                }
            }
        }
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn optional_native_cache_keys_distinguish_all_feature_combinations_and_frames() {
    let mut cpu = configured(0, 0xd503_201f);
    let mut keys = std::collections::HashSet::new();
    for frame in [0, 0x1000, 0x1234_0000_0000_0000] {
        cpu.sysregs.el1.ttbr0 = frame;
        for bits in 0..256 {
            cpu.config
                .features
                .remove(optional::FEATURES | ArmFeatures::FP16 | ArmFeatures::FHM);
            cpu.config.features |= selected((bits & 63) as u8);
            cpu.config.features.set(ArmFeatures::FP16, bits & 64 != 0);
            cpu.config.features.set(ArmFeatures::FHM, bits & 128 != 0);
            assert!(
                keys.insert(cpu.jit_mode_tag()),
                "frame={frame:x}, bits={bits:02x}"
            );
        }
    }
    assert_eq!(keys.len(), 768);
}

#[test]
fn optional_independent_reserved_controls_preserve_base_fsqrt_and_frecpx() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a64-optional-fp-profile/reserved-controls.json"
    )))
    .unwrap();
    for case in cases["records"].as_array().unwrap() {
        let word = case["word"].as_u64().unwrap() as u32;
        for el in [0, 1] {
            for fpen in [0, 3] {
                let mut cpu = configured(63, word);
                cpu.config
                    .features
                    .insert(ArmFeatures::FP16 | ArmFeatures::FHM);
                cpu.update_fp_id_registers();
                cpu.current_el = el;
                cpu.sp_sel = el != 0;
                cpu.sysregs.el1.cpacr = fpen << 20;
                let before = (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.pstate_bits());
                let result = cpu.step();
                match case["expected"][fpen.to_string()].as_str().unwrap() {
                    "P" => {
                        assert_eq!(result.unwrap(), CpuExit::Continue, "{word:08x}");
                        assert_eq!((cpu.pc, cpu.insn_count), (0x1004, 1));
                        continue;
                    }
                    "U" => assert!(
                        matches!(result, Err(ArmError::UndefinedInstruction(w)) if w == word),
                        "{word:08x}: {result:?}"
                    ),
                    "D" => assert!(
                        matches!(result, Err(ArmError::ArchitecturalException { ec: 7, .. })),
                        "{word:08x}: {result:?}"
                    ),
                    other => panic!("unexpected oracle event {other}"),
                }
                assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (0x1000, 0, 0));
                assert_eq!(
                    (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.pstate_bits()),
                    before
                );
            }
        }
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn optional_native_metadata_guards_each_capability() {
    use std::sync::Arc;
    for (feature, ..) in CASES {
        let mut cpu = configured(63, 0x9100_0400);
        let bytes = [0x9100_0400u32, 0xf100_0803, 0x54ff_ffc3, 0xd420_0000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        cpu.write_memory(0x1000, &bytes).unwrap();
        cpu.x[0] = 0;
        let mut region = cpu.jit_compile_region().expect("integer native control");
        assert!(region.fp_features.is_empty());
        assert!(cpu.jit_run_region(&region));
        assert_eq!((cpu.pc, cpu.x[0]), (0x100c, 2));
        // Real integer code with synthetic metadata tests the shared guard;
        // instruction-specific native support is tested separately below.
        region.fp_features = feature;
        let region = Arc::new(region);
        let enabled = cpu.jit_mode_tag();
        cpu.jit
            .cache
            .insert((0x1000, enabled), Some(region.clone()));
        cpu.config.features.remove(feature);
        cpu.update_fp_id_registers();
        cpu.pc = 0x1000;
        cpu.x[0] = 0;
        let before = (cpu.pc, cpu.x, cpu.v, cpu.insn_count);
        assert!(!cpu.jit_run_region(&region), "{feature:?}");
        assert_eq!((cpu.pc, cpu.x, cpu.v, cpu.insn_count), before);
        let denied = cpu.jit_mode_tag();
        assert_ne!(enabled, denied);
        cpu.jit.cache.insert((0x1000, denied), Some(region.clone()));
        assert!(cpu.jit_lookup(0x1000).is_none());
        cpu.config.features.insert(feature);
        cpu.update_fp_id_registers();
        assert_eq!(cpu.jit_mode_tag(), enabled);
        assert!(Arc::ptr_eq(&cpu.jit_lookup(0x1000).unwrap(), &region));
        assert!(cpu.jit_run_region(&region));
        assert_eq!((cpu.pc, cpu.x[0]), (0x100c, 2));
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn optional_native_instruction_frontiers_retain_original_dependencies() {
    let witnesses: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a64-optional-fp-profile/native-witnesses.json"
    )))
    .unwrap();
    for case in witnesses["selected"].as_array().unwrap() {
        let word = case["word"].as_u64().unwrap() as u32;
        let feature = ArmFeatures::from_name(case["feature"].as_str().unwrap()).unwrap();
        let code = [
            0x9100_0694u32,
            word,
            0x9e67_03e0,
            0xaa1f_03e0,
            0xf100_0a83,
            0x54ff_ff63,
            0xd420_0000,
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
        let prepare = || {
            let mut cpu = configured(63, word);
            cpu.config
                .features
                .insert(ArmFeatures::FP16 | ArmFeatures::FHM);
            cpu.update_fp_id_registers();
            cpu.write_memory(0x1000, &code).unwrap();
            cpu
        };
        let mut cpu = prepare();
        let enabled = cpu.jit_compile_region();
        eprintln!(
            "optional native {word:08x} {} admitted={}",
            case["name"],
            enabled.is_some()
        );
        if let Some(region) = enabled {
            assert!(cpu.jit_run_region(&region));
            let mut reference = prepare();
            for _ in 0..64 {
                if reference.pc == cpu.pc && reference.insn_count != 0 {
                    break;
                }
                assert_eq!(reference.step().unwrap(), CpuExit::Continue);
            }
            assert_eq!(
                (cpu.pc, cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.nzcv),
                (
                    reference.pc,
                    reference.x,
                    reference.v,
                    reference.fpcr,
                    reference.fpsr,
                    reference.nzcv
                )
            );
            if cpu.pc > 0x1004 {
                assert!(region.fp_features.contains(feature), "{word:08x}");
            }
        }
        let mut denied = prepare();
        denied.config.features.remove(feature);
        denied.update_fp_id_registers();
        if let Some(region) = denied.jit_compile_region() {
            assert!(!region.fp_features.contains(feature));
            assert!(denied.jit_run_region(&region));
            assert_eq!(
                denied.pc, 0x1004,
                "native must stop before absent {feature:?}"
            );
            assert!(matches!(denied.step(), Err(ArmError::UndefinedInstruction(w)) if w == word));
        }
    }
}

#[test]
fn optional_host_selection_preserves_pending_fault_and_private_checkpoint() {
    use crate::isa::arm::aarch64::cpu::CoreCheckpoint;
    let mut cpu = configured(0, 0x1e22_2820);
    cpu.current_el = 0;
    cpu.sp_sel = false;
    cpu.sysregs.el1.cpacr = 0;
    cpu.sysregs.el1.vbar = 0x2000;
    cpu.sysregs.cntpct_el0 = 0x1234;
    cpu.insn_count = 17;
    cpu.cycle_count = 41;
    // Synthetic delayed native event: the configuration test does not claim
    // that this pending event was generated by new native FP execution.
    cpu.execution.native_fault = Some(ArmError::ArchitecturalException {
        ec: 7,
        iss: 0,
        target_el: None,
    });
    let before = CoreCheckpoint::capture(&cpu).unwrap();
    assert!(cpu.select_fp_features(ArmFeatures::PACA).is_err());
    assert_eq!(CoreCheckpoint::capture(&cpu).unwrap(), before);
    let registers = (cpu.pc, cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.pstate_bits());
    let selected = optional::FEATURES | ArmFeatures::FP16 | ArmFeatures::FHM;
    cpu.select_fp_features(selected).unwrap();
    assert_eq!(cpu.selected_fp_features(), selected);
    assert_eq!(
        (cpu.pc, cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.pstate_bits()),
        registers
    );
    assert_eq!(
        (cpu.insn_count, cpu.cycle_count, cpu.sysregs.cntpct_el0),
        (17, 41, 0x1234)
    );
    assert!(matches!(
        cpu.execution.native_fault.as_ref(),
        Some(ArmError::ArchitecturalException { ec: 7, .. })
    ));
    let checkpoint = CoreCheckpoint::capture(&cpu).unwrap();
    let bytes = crate::codec::serialize_limited(&checkpoint, 1024 * 1024).unwrap();
    let restored: CoreCheckpoint =
        crate::codec::deserialize_limited::<_, { 1024 * 1024 }>(&bytes).unwrap();
    let mut target = AArch64Cpu::new(
        restored.configuration(),
        Box::new(FlatMemory::new(0, 0x5000)),
    );
    target
        .write_memory(0x2400, &0x9100_0529u32.to_le_bytes())
        .unwrap(); // ADD X9,X9,#1
    restored.install_in_prepared(&mut target).unwrap();
    assert_eq!(CoreCheckpoint::capture(&target).unwrap(), checkpoint);
    assert_eq!(target.step_system().unwrap(), CpuExit::Continue);
    assert_eq!(
        (target.pc, target.insn_count, target.cycle_count),
        (0x2400, 17, 41)
    );
    assert_eq!(
        (target.sysregs.el1.elr, target.sysregs.el1.esr >> 26),
        (0x1000, 7)
    );
    assert_eq!(target.sysregs.cntpct_el0, 0x1234);
    assert!(target.execution.native_fault.is_none());
    assert_eq!(target.step_system().unwrap(), CpuExit::Continue);
    assert_eq!(
        (
            target.pc,
            target.insn_count,
            target.cycle_count,
            target.x[9]
        ),
        (0x2404, 18, 42, 1)
    );
    assert_eq!(target.sysregs.cntpct_el0, 0x1244);
}

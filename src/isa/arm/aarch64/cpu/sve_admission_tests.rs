//! Optional SVE instruction capabilities precede execution-time access traps.
use super::*;
use crate::isa::arm::common::memory::FlatMemory;

const ENTRY: u64 = 0x100;

// Independent LLVM encodings retained in the existing differential corpus.
const CASES: [(u32, ArmFeatures, ArmFeatures); 9] = [
    (0x4542_0020, ArmFeatures::SVE2, ArmFeatures::SVE2), // SADDLB
    (
        0x4502_b020,
        ArmFeatures::SVE2_BITPERM.union(ArmFeatures::SVE2),
        ArmFeatures::SVE2_BITPERM,
    ), // BEXT
    (0x6462_8020, ArmFeatures::BF16, ArmFeatures::BF16), // BFDOT
    (0x4502_9820, ArmFeatures::I8MM, ArmFeatures::I8MM), // SMMLA
    (0x64a2_e420, ArmFeatures::SVE_F32MM, ArmFeatures::SVE_F32MM), // FMMLA
    (
        0x052b_2420,
        ArmFeatures::SVE2P1.union(ArmFeatures::SVE2),
        ArmFeatures::SVE2P1,
    ), // DUPQ
    (
        0x6502_0020,
        ArmFeatures::SVE_B16B16.union(ArmFeatures::SVE2),
        ArmFeatures::SVE_B16B16,
    ), // BFADD
    (
        0x4502_6820,
        ArmFeatures::SVE2_AES.union(ArmFeatures::SVE2),
        ArmFeatures::SVE2_AES,
    ), // PMULLB .q: FEAT_SVE_AES and FEAT_SVE_PMULL128 are mutually dependent.
    (
        0x4522_e020,
        ArmFeatures::SVE2_AES.union(ArmFeatures::SVE2),
        ArmFeatures::SVE2_AES,
    ), // AESE: the existing AES policy bit selects both primary predicates.
];

fn cpu(word: u32, optional: ArmFeatures, zen: u64) -> AArch64Cpu {
    let mut cpu = AArch64Cpu::new(
        AArch64Config {
            initial_el: 1,
            gic_config: None,
            features: ArmFeatures::armv8_0_base() | ArmFeatures::SVE | optional,
            ..Default::default()
        },
        Box::new(FlatMemory::new(0, 0x1000)),
    );
    cpu.pc = ENTRY;
    cpu.btype = 2;
    cpu.v.fill(0x3f80_0000_3f80_0000_3f80_0000_3f80_0000);
    cpu.sve_p.fill(0xffff);
    cpu.sve_ffr = 0x5555;
    cpu.sysregs.el1.cpacr = (3 << 20) | (zen << 16);
    cpu.sysregs
        .impl_defined
        .insert(Aarch64SysRegEncoding::new(3, 6, 1, 1, 2).encode(), 1 << 8);
    cpu.write_memory(ENTRY, &word.to_le_bytes()).unwrap();
    cpu
}

fn absent(index: usize) {
    let (word, selected, removed) = CASES[index];
    for zen in [3, 0] {
        let mut cpu = cpu(word, selected - removed, zen);
        let before = (
            cpu.pc,
            cpu.x,
            cpu.v,
            cpu.sve_p,
            cpu.sve_ffr,
            cpu.pstate_bits(),
        );
        let result = cpu.step();
        assert!(
            matches!(result, Err(ArmError::UndefinedInstruction(raw)) | Ok(CpuExit::Undefined(raw)) if raw == word),
            "word={word:08x} missing={removed:?} ZEN={zen}: {result:?}"
        );
        assert_eq!((cpu.insn_count, cpu.cycle_count), (0, 0));
        assert_eq!(
            (
                cpu.pc,
                cpu.x,
                cpu.v,
                cpu.sve_p,
                cpu.sve_ffr,
                cpu.pstate_bits()
            ),
            before
        );
    }
}

#[test]
fn selected_optional_forms_execute_as_positive_controls() {
    for (word, selected, _) in CASES {
        let mut cpu = cpu(word, selected, 3);
        assert_eq!(
            cpu.step().unwrap(),
            CpuExit::Continue,
            "{word:08x} {selected:?}"
        );
        assert_eq!((cpu.pc, cpu.insn_count), (ENTRY + 4, 1));
    }
}

#[test]
fn absent_sve2_is_undefined_before_permissions() {
    absent(0);
}
#[test]
fn absent_bitperm_is_undefined_before_permissions() {
    absent(1);
}
#[test]
fn absent_bf16_is_undefined_before_permissions() {
    absent(2);
}
#[test]
fn absent_i8mm_is_undefined_before_permissions() {
    absent(3);
}
#[test]
fn absent_f32mm_is_undefined_before_permissions() {
    absent(4);
}
#[test]
fn absent_sve2p1_is_undefined_before_permissions() {
    absent(5);
}
#[test]
fn absent_b16b16_is_undefined_before_permissions() {
    absent(6);
}

#[test]
fn absent_sve_aes_disables_pmull128_before_permissions() {
    absent(7);
}

#[test]
fn absent_sve_aes_is_undefined_before_permissions() {
    absent(8);
}

#[test]
fn conditional_streaming_predicate_access_uses_its_selected_access_policy() {
    // LLVM 23 / Arm XML 2025-12: PTRUE PN8.B. The operation selects
    // CheckSVEEnabled with SVE2p1, otherwise CheckStreamingSVEEnabled.
    const WORD: u32 = 0x2520_7810;
    for (sve2p1, smen, zen, ec, iss) in [
        (false, 3, 0, 0x1d, 2),
        (false, 0, 3, 0x1d, 0),
        (true, 0, 0, 0x19, 0),
    ] {
        let mut cpu = cpu(
            WORD,
            ArmFeatures::SVE2 | ArmFeatures::SME | ArmFeatures::SME2,
            zen,
        );
        cpu.config.features.set(ArmFeatures::SVE2P1, sve2p1);
        cpu.sysregs.el1.cpacr |= smen << 24;
        cpu.sysregs.impl_defined.insert(
            Aarch64SysRegEncoding::new(3, 6, 1, 1, 2).encode(),
            (1 << 8) | (1 << 12),
        );
        let before = (
            cpu.pc,
            cpu.x,
            cpu.v,
            cpu.sve_p,
            cpu.sve_ffr,
            cpu.pstate_bits(),
        );
        let result = cpu.step();
        assert!(
            matches!(result,
            Err(ArmError::ArchitecturalException { ec: actual_ec, iss: actual_iss, target_el: None })
                if actual_ec == ec && actual_iss == iss),
            "SVE2p1={sve2p1} SMEN={smen} ZEN={zen}: {result:?}"
        );
        assert_eq!(
            (
                cpu.pc,
                cpu.x,
                cpu.v,
                cpu.sve_p,
                cpu.sve_ffr,
                cpu.pstate_bits()
            ),
            before
        );
        assert_eq!((cpu.insn_count, cpu.cycle_count), (0, 0));
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn conditional_native_access_keeps_sve2p1_dependency_at_entry() {
    use crate::smir::ir::ops::{OpKind, SmirOp};
    use crate::smir::ir::types::{BlockId, FunctionId, OpId};
    use crate::smir::ir::{SmirBlock, SmirFunction};
    const WORD: u32 = 0x2520_7810; // PTRUE PN8.B
    let mut cpu = cpu(
        WORD,
        ArmFeatures::SVE2 | ArmFeatures::SVE2P1 | ArmFeatures::SME | ArmFeatures::SME2,
        3,
    );
    let mut function = SmirFunction::new(FunctionId(0), BlockId(0), ENTRY);
    let mut block = SmirBlock::new(BlockId(0), ENTRY);
    block.push_op(SmirOp::new(OpId(0), ENTRY, OpKind::Nop));
    function.add_block(block);
    let (access, features) = cpu
        .native_requirements(&function, ENTRY, &WORD.to_le_bytes())
        .unwrap();

    // Pair the original-word requirements with real integer native code.
    // This verifies its entry guard without asserting native SVE support.
    let code = [0x9100_0400u32, 0xf100_081f, 0x54ff_ffc3, 0xd420_0000]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    cpu.write_memory(ENTRY, &code).unwrap();
    let mut region = cpu
        .jit_compile_region()
        .expect("integer native positive control");
    region.fp_access = access;
    region.fp_features = features;
    assert!(cpu.jit_run_region(&region));
    assert_eq!((cpu.pc, cpu.x[0]), (ENTRY + 12, 2));

    cpu.pc = ENTRY;
    cpu.x[0] = 0;
    cpu.config.features.remove(ArmFeatures::SVE2P1);
    let before = (cpu.pc, cpu.x, cpu.v, cpu.insn_count);
    assert!(
        !cpu.jit_run_region(&region),
        "missing conditional SVE2p1 guard: {features:?}"
    );
    assert_eq!((cpu.pc, cpu.x, cpu.v, cpu.insn_count), before);
    assert!(features.contains(ArmFeatures::SVE2P1));
}

#[test]
fn scalar_sme_access_uses_smen_before_any_sve_permission_check() {
    for word in [0x04bf_5820, 0x0421_5820, 0x0461_5820] {
        for sve in [false, true] {
            let mut cpu = cpu(word, ArmFeatures::SME, 3);
            cpu.config.features.set(ArmFeatures::SVE, sve);
            let before = (cpu.pc, cpu.x, cpu.v, cpu.sve_p, cpu.pstate_bits());
            assert!(
                matches!(
                    cpu.step(),
                    Err(ArmError::ArchitecturalException {
                        ec: 0x1d,
                        iss: 0,
                        target_el: None
                    })
                ),
                "{word:08x} SVE={sve}"
            );
            assert_eq!((cpu.pc, cpu.x, cpu.v, cpu.sve_p, cpu.pstate_bits()), before);
            assert_eq!((cpu.insn_count, cpu.cycle_count), (0, 0));
        }
    }
}

fn qemu_cases() -> serde_json::Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a64-sve-profile/oracle-cases.json"
    )))
    .unwrap()
}

fn qemu_cpu(case: &serde_json::Value) -> AArch64Cpu {
    let word = case["opcode"].as_u64().unwrap() as u32;
    let mut cpu = cpu(
        word,
        super::sve::admission::FEATURES,
        case["zen"].as_u64().unwrap(),
    );
    let model = case["model"].as_str().unwrap();
    if model.contains("sme=off") {
        cpu.config
            .features
            .remove(ArmFeatures::SME | ArmFeatures::SME2);
    }
    if model.contains("sve=off") {
        cpu.config.features.remove(ArmFeatures::SVE);
    }
    cpu.sysregs.scr_el3 = 1 | (1 << 10);
    cpu.sysregs.hcr_el2 = 1 << 31;
    cpu.sysregs.el1.cpacr |= case["smen"].as_u64().unwrap() << 24;
    cpu.sysregs.impl_defined.insert(
        Aarch64SysRegEncoding::new(3, 6, 1, 1, 2).encode(),
        (1 << 8) | (1 << 12),
    );
    cpu
}

#[test]
fn independent_qemu_profile_results_replay_without_weakening_fault_checks() {
    let cases = qemu_cases();
    let cases = cases["profiles"].as_array().unwrap();
    assert_eq!(cases.len(), 51);
    for case in cases {
        let mut cpu = qemu_cpu(case);
        let before = (
            cpu.pc,
            cpu.x,
            cpu.v,
            cpu.sve_p,
            cpu.sve_ffr,
            cpu.pstate_bits(),
        );
        let expected = case["raw_stderr"].as_str().unwrap();
        let result = cpu.step();
        if expected == "13cA0" {
            assert_eq!(result.unwrap(), CpuExit::Continue, "{case}");
            assert_eq!((cpu.pc, cpu.insn_count), (ENTRY + 4, 1), "{case}");
        } else {
            if expected == "100I0" {
                let word = case["opcode"].as_u64().unwrap() as u32;
                assert!(
                    matches!(result,
                    Err(ArmError::UndefinedInstruction(raw)) | Ok(CpuExit::Undefined(raw))
                        if raw == word),
                    "{case}: {result:?}"
                );
            } else {
                let expected_ec = u8::from_str_radix(&expected[1..3], 16).unwrap();
                assert!(
                    matches!(result,
                    Err(ArmError::ArchitecturalException { ec, iss: 0, target_el: None })
                        if ec == expected_ec),
                    "{case}: {result:?}"
                );
            }
            assert_eq!(
                (
                    cpu.pc,
                    cpu.x,
                    cpu.v,
                    cpu.sve_p,
                    cpu.sve_ffr,
                    cpu.pstate_bits()
                ),
                before,
                "{case}"
            );
            assert_eq!((cpu.insn_count, cpu.cycle_count), (0, 0));
        }
    }
}

#[test]
fn scalar_sme_length_values_replay_the_independent_qemu_results() {
    let cases = qemu_cases();
    let cases = cases["scalar_values"].as_array().unwrap();
    assert_eq!(cases.len(), 24);
    for case in cases {
        let mut cpu = qemu_cpu(case);
        cpu.sp_sel = true;
        cpu.set_current_sp(case["initial_sp"].as_u64().unwrap());
        cpu.set_x(1, case["initial_base"].as_u64().unwrap());
        let before = (
            cpu.v,
            cpu.sve_p,
            cpu.sve_ffr,
            cpu.fpcr,
            cpu.fpsr,
            cpu.pstate_bits(),
        );
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue, "{case}");
        let capture = case["capture"].as_str().unwrap();
        let actual = if capture == "sp" {
            cpu.get_sp()
        } else {
            cpu.get_x(capture[1..].parse().unwrap())
        };
        let raw = case["raw_stderr"]
            .as_str()
            .unwrap()
            .split_once(':')
            .unwrap()
            .1;
        assert_eq!(actual, u64::from_str_radix(raw, 16).unwrap(), "{case}");
        // Retirement clears BTYPE, so compare the instruction's independent
        // NZCV field rather than requiring the complete old PSTATE value.
        assert_eq!(
            (cpu.v, cpu.sve_p, cpu.sve_ffr, cpu.fpcr, cpu.fpsr),
            (before.0, before.1, before.2, before.3, before.4)
        );
        assert_eq!(cpu.pstate_bits() & 0xf000_0000, before.5 & 0xf000_0000);
        assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (ENTRY + 4, 1, 1));
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn native_admission_retains_original_optional_capabilities_before_optimization() {
    use crate::smir::ir::ops::{OpKind, SmirOp};
    use crate::smir::ir::types::{BlockId, FunctionId, OpId};
    use crate::smir::ir::{SmirBlock, SmirFunction};
    let mut function = SmirFunction::new(FunctionId(0), BlockId(0), ENTRY);
    let mut block = SmirBlock::new(BlockId(0), ENTRY);
    block.push_op(SmirOp::new(OpId(0), ENTRY, OpKind::Nop));
    function.add_block(block);
    for (word, optional, removed) in CASES {
        let mut cpu = cpu(word, optional, 3);
        let (access, features) = cpu
            .native_requirements(&function, ENTRY, &word.to_le_bytes())
            .unwrap();
        assert!(access.sve, "{word:08x}");
        assert!(features.contains(removed | ArmFeatures::SVE), "{word:08x}");
        cpu.config.features.remove(removed);
        assert!(
            cpu.native_requirements(&function, ENTRY, &word.to_le_bytes())
                .is_none(),
            "{word:08x} removed {removed:?}"
        );
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn optional_profile_changes_cannot_reuse_a_native_negative_cache_entry() {
    for (word, optional, removed) in CASES {
        let mut cpu = cpu(word, optional - removed, 3);
        let denied = cpu.jit_mode_tag();
        cpu.jit.cache.insert((ENTRY, denied), None);
        cpu.config.features.insert(removed);
        let enabled = cpu.jit_mode_tag();
        assert_ne!(enabled, denied, "{word:08x} {removed:?}");
        cpu.config.features.remove(removed);
        assert_eq!(cpu.jit_mode_tag(), denied);
    }
}

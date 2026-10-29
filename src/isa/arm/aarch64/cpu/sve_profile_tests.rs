//! Original SVE capability and normal-execution access controls.
use super::{AArch64Config, AArch64Cpu, ArmCpu, ArmError, ArmFeatures, CpuExit};
use crate::isa::arm::common::memory::FlatMemory;
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;

const ENTRY: u64 = 0x100;
const DATA: u64 = 0x800;
const EZ: u64 = 1 << 8;
const TZ: u64 = 1 << 8;
const TFP: u64 = 1 << 10;
const RW: u64 = 1 << 31;
const E2H: u64 = 1 << 34;
const TGE: u64 = 1 << 27;
const WORDS: [u32; 7] = [
    0x2518_e3e0,
    0x04a2_0020,
    0x6582_0020,
    0xa400_a060,
    0xe400_e060,
    0x04bf_5020,
    0x0420_e3e0,
];

fn cptr(cpu: &mut AArch64Cpu, op1: u8, value: u64) {
    cpu.sysregs
        .impl_defined
        .insert(Aarch64SysRegEncoding::new(3, op1, 1, 1, 2).encode(), value);
}

fn cpu(word: u32, el: u8) -> AArch64Cpu {
    let config = AArch64Config {
        initial_el: el,
        features: ArmFeatures::armv8_0_base() | ArmFeatures::SVE | ArmFeatures::VHE,
        gic_config: None,
        ..Default::default()
    };
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x4000)));
    cpu.pc = ENTRY;
    cpu.sp_sel = el != 0;
    cpu.btype = 2;
    cpu.x[0] = 0xdead;
    cpu.x[3] = DATA;
    cpu.v.fill(0x3f80_0000_3f80_0000_3f80_0000_3f80_0000);
    cpu.sve_p.fill(0xffff);
    cpu.sve_ffr = 0x5a5a;
    cpu.sysregs.scr_el3 = 1 | (1 << 10);
    cpu.sysregs.hcr_el2 = RW;
    cpu.sysregs.el1.cpacr = (3 << 16) | (3 << 20);
    cpu.sysregs.el1.vbar = 0x1000;
    cpu.sysregs.el2.vbar = 0x1800;
    cpu.sysregs.el3.vbar = 0x2000;
    cptr(&mut cpu, 4, 0);
    cptr(&mut cpu, 6, EZ);
    cpu.write_memory(ENTRY, &word.to_le_bytes()).unwrap();
    cpu.write_memory(DATA, &[0xa5; 32]).unwrap();
    cpu
}

fn check(cpu: &mut AArch64Cpu, expected: Option<(u8, u8)>) {
    let before = (
        cpu.pc,
        cpu.x,
        cpu.v,
        cpu.sve_p,
        cpu.sve_ffr,
        cpu.fpcr,
        cpu.fpsr,
        cpu.pstate_bits(),
    );
    let memory = cpu.read_memory(DATA, 32).unwrap();
    let result = cpu.step();
    if let Some((ec, target)) = expected {
        assert!(
            matches!(result, Err(ArmError::ArchitecturalException { ec: actual, iss: 0, target_el }) if actual == ec && target_el.unwrap_or(1) == target),
            "expected EC={ec:#x} EL{target}, got {result:?}"
        );
        assert_eq!((cpu.insn_count, cpu.cycle_count), (0, 0));
        assert_eq!(
            (
                cpu.pc,
                cpu.x,
                cpu.v,
                cpu.sve_p,
                cpu.sve_ffr,
                cpu.fpcr,
                cpu.fpsr,
                cpu.pstate_bits()
            ),
            before
        );
        assert_eq!(cpu.read_memory(DATA, 32).unwrap(), memory);
    } else {
        assert_eq!(result.unwrap(), CpuExit::Continue);
        assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (ENTRY + 4, 1, 1));
    }
}

#[test]
fn base_sve_absence_is_decode_failure_before_permissions() {
    for word in WORDS {
        for zen in 0..4 {
            let mut cpu = cpu(word, 1);
            cpu.config.features.remove(ArmFeatures::SVE);
            cpu.sysregs.el1.cpacr = (zen << 16) | (3 << 20);
            assert!(
                matches!(cpu.step(), Err(ArmError::UndefinedInstruction(raw)) if raw == word),
                "word={word:08x}, ZEN={zen}"
            );
            assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (ENTRY, 0, 0));
        }
    }
}

#[test]
fn local_sve_and_fp_controls_have_interleaved_priority() {
    for word in WORDS {
        for el in [0, 1] {
            for zen in 0..4 {
                for fpen in 0..4 {
                    let mut cpu = cpu(word, el);
                    cpu.sysregs.el1.cpacr = (zen << 16) | (fpen << 20);
                    let disabled = |field: u64| field & 1 == 0 || (el == 0 && field != 3);
                    let expected = if disabled(zen) {
                        Some((0x19, 1))
                    } else if disabled(fpen) {
                        Some((7, 1))
                    } else {
                        None
                    };
                    check(&mut cpu, expected);
                }
            }
        }
    }
}

#[test]
fn higher_sve_and_fp_controls_follow_level_and_class_priority() {
    for word in WORDS {
        for el in [0, 1, 2, 3] {
            for (el2, el3) in [
                (TZ, 0),
                (TFP, 0),
                (TZ | TFP, EZ | TFP),
                (0, 0),
                (0, EZ | TFP),
                (0, EZ),
            ] {
                let mut cpu = cpu(word, el);
                cptr(&mut cpu, 4, el2);
                cptr(&mut cpu, 6, el3);
                let expected = if el <= 2 && el2 & TZ != 0 {
                    Some((0x19, 2))
                } else if el <= 2 && el2 & TFP != 0 {
                    Some((7, 2))
                } else if el3 & EZ == 0 {
                    Some((0x19, 3))
                } else if el3 & TFP != 0 {
                    Some((7, 3))
                } else {
                    None
                };
                check(&mut cpu, expected);
            }
        }
    }
}

#[test]
fn host_vhe_fields_bypass_local_controls_and_preserve_sve_before_fp() {
    for word in WORDS {
        for el in [0, 2] {
            for zen in 0..4 {
                for fpen in 0..4 {
                    let mut cpu = cpu(word, el);
                    cpu.sysregs.hcr_el2 = RW | E2H | TGE;
                    cpu.sysregs.el1.cpacr = 0;
                    cptr(&mut cpu, 4, (zen << 16) | (fpen << 20));
                    let disabled = |field: u64| field & 1 == 0 || (el == 0 && field != 3);
                    let expected = if disabled(zen) {
                        Some((0x19, 2))
                    } else if disabled(fpen) {
                        Some((7, 2))
                    } else {
                        None
                    };
                    check(&mut cpu, expected);
                }
            }
        }
    }
}

#[test]
fn local_sve_tge_redirection_retains_sve_exception_class() {
    for word in WORDS {
        let mut cpu = cpu(word, 0);
        cpu.sysregs.hcr_el2 = RW | TGE;
        cpu.sysregs.el1.cpacr = 3 << 20;
        check(&mut cpu, Some((0x19, 2)));
    }
}

#[test]
fn secure_state_ignores_nonsecure_el2_traps() {
    for word in WORDS {
        let mut cpu = cpu(word, 1);
        cpu.sysregs.scr_el3 = 1 << 10;
        cptr(&mut cpu, 4, TZ | TFP);
        check(&mut cpu, None);
    }
}

#[test]
fn system_delivery_preserves_fault_pc_class_and_zero_retirement() {
    for word in WORDS {
        for (el, zen, el2, el3, target, ec) in [
            (0, 0, 0, EZ, 1, 0x19),
            (1, 2, 0, EZ, 1, 0x19),
            (1, 3, TZ, EZ, 2, 0x19),
            (1, 3, TFP, 0, 2, 7),
            (1, 3, 0, 0, 3, 0x19),
        ] {
            let mut cpu = cpu(word, el);
            cpu.sysregs.el1.cpacr = (zen << 16) | (3 << 20);
            cptr(&mut cpu, 4, el2);
            cptr(&mut cpu, 6, el3);
            cpu.step_system().unwrap();
            assert_eq!(cpu.current_el, target);
            assert_eq!(cpu.sysregs.bank(target).elr, ENTRY);
            assert_eq!(cpu.sysregs.bank(target).esr >> 26, ec);
            assert_eq!((cpu.insn_count, cpu.cycle_count), (0, 0));
        }
    }
}

#[test]
fn sme_only_nonstreaming_access_uses_sme_controls_before_not_streaming() {
    for word in WORDS {
        for el in [0, 1, 2, 3] {
            let mut cpu = cpu(word, el);
            cpu.config.features.remove(ArmFeatures::SVE);
            cpu.config.features.insert(ArmFeatures::SME);
            cpu.sysregs.el1.cpacr = (3 << 24) | (3 << 20);
            cptr(&mut cpu, 6, 1 << 12);
            let result = cpu.step();
            let target = el.max(1);
            assert!(
                matches!(result, Err(ArmError::ArchitecturalException { ec: 0x1d, iss: 2, target_el }) if target_el.unwrap_or(1) == target),
                "{word:08x} EL{el}: {result:?}"
            );
            assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (ENTRY, 0, 0));
        }
    }
}

#[test]
fn sme_only_access_denials_preserve_sme_before_fp_priority() {
    for word in WORDS {
        for (smen, fpen, c2, c3, expected) in [
            (0, 0, 0, 1 << 12, (0x1d, 1)),
            (3, 0, 0, 1 << 12, (7, 1)),
            (3, 3, 1 << 12, 1 << 12, (0x1d, 2)),
            (3, 3, TFP, 0, (7, 2)),
            (3, 3, 0, 0, (0x1d, 3)),
        ] {
            let mut cpu = cpu(word, 1);
            cpu.config.features.remove(ArmFeatures::SVE);
            cpu.config.features.insert(ArmFeatures::SME);
            cpu.sysregs.el1.cpacr = (smen << 24) | (fpen << 20);
            cptr(&mut cpu, 4, c2);
            cptr(&mut cpu, 6, c3);
            check(&mut cpu, Some(expected));
        }
    }
}

#[test]
fn all_independent_qemu_profiles_replay_the_reported_fault_frontiers() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a64-sve-access/oracle-cases.json"
    )))
    .unwrap();
    let cases = cases.as_array().unwrap();
    assert_eq!(cases.len(), 504);
    for case in cases {
        let p = &case["profile"];
        let mut cpu = cpu(
            case["opcode"].as_u64().unwrap() as u32,
            p["el"].as_u64().unwrap() as u8,
        );
        cpu.config
            .features
            .set(ArmFeatures::SVE, p["present"].as_bool().unwrap());
        cpu.config
            .features
            .set(ArmFeatures::SME, p["sme_only"].as_bool().unwrap());
        cpu.sysregs.scr_el3 = (1 << 10) | u64::from(p["secure"].as_u64().unwrap() == 0);
        cpu.sysregs.hcr_el2 = p["hcr"].as_u64().unwrap();
        cpu.sysregs.el1.cpacr = (p["zen"].as_u64().unwrap() << 16)
            | (p["fpen"].as_u64().unwrap() << 20)
            | (p["smen"].as_u64().unwrap() << 24);
        cptr(&mut cpu, 4, p["cptr2"].as_u64().unwrap());
        cptr(&mut cpu, 6, p["cptr3"].as_u64().unwrap());
        let before = (
            cpu.x,
            cpu.v,
            cpu.sve_p,
            cpu.sve_ffr,
            cpu.fpcr,
            cpu.fpsr,
            cpu.pstate_bits(),
        );
        let memory = cpu.read_memory(DATA, 32).unwrap();
        cpu.step_system().unwrap();
        if case["fault"].as_bool().unwrap() {
            let target = case["target"].as_u64().unwrap() as u8;
            assert_eq!(cpu.current_el, target, "{case}");
            let bank = cpu.sysregs.bank(target);
            assert_eq!(bank.elr, ENTRY, "{case}");
            assert_eq!(bank.esr >> 26, case["ec"].as_u64().unwrap(), "{case}");
            assert_eq!(bank.esr & 7, case["iss"].as_u64().unwrap(), "{case}");
            assert_eq!(bank.spsr, before.6, "{case}");
            assert_eq!(
                (cpu.x, cpu.v, cpu.sve_p, cpu.sve_ffr, cpu.fpcr, cpu.fpsr),
                (before.0, before.1, before.2, before.3, before.4, before.5),
                "{case}"
            );
            assert_eq!(cpu.read_memory(DATA, 32).unwrap(), memory, "{case}");
            assert_eq!((cpu.insn_count, cpu.cycle_count), (0, 0), "{case}");
        } else {
            assert_eq!(
                (cpu.pc, cpu.insn_count, cpu.cycle_count),
                (ENTRY + 4, 1, 1),
                "{case}"
            );
        }
    }
}

#[test]
fn legacy_core_record_reencodes_without_new_state_fields_or_tags() {
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a64-sve-access/fixtures/parent-core.bin"
    ));
    let state: super::CoreCheckpoint = crate::codec::deserialize_strict(bytes).unwrap();
    assert_eq!(crate::codec::serialize(&state).unwrap(), bytes);
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn scalable_native_requirements_and_cache_keys_follow_dynamic_denials() {
    use crate::isa::arm::common::fp_access::{FpAccessClass, FpAccessRequirements};
    for word in WORDS {
        let mut cpu = cpu(word, 1);
        let mut requirements = FpAccessRequirements::default();
        requirements.observe(word);
        let enabled = cpu.jit_mode_tag();
        assert!(requirements.permitted(cpu.fp_access_controls()));
        cpu.sysregs.el1.cpacr = 3 << 20;
        assert!(
            cpu.fp_access_controls()
                .fault(FpAccessClass::Data)
                .is_none()
        );
        assert!(!requirements.permitted(cpu.fp_access_controls()));
        let denied = cpu.jit_mode_tag();
        assert_ne!(enabled, denied);
        cpu.jit.cache.insert((ENTRY, denied), None);
        cpu.sysregs.el1.cpacr = (3 << 16) | (3 << 20);
        assert_eq!(cpu.jit_mode_tag(), enabled);
        cpu.config.features.remove(ArmFeatures::SVE);
        assert_ne!(cpu.jit_mode_tag(), enabled);
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn unsupported_scalable_native_regions_fall_back_at_the_same_fault_frontier() {
    for word in WORDS {
        let mut cpu = cpu(word, 1);
        assert!(
            cpu.jit_compile_region().is_none(),
            "unexpected native support for {word:08x}"
        );
        cpu.jit.hot.insert(ENTRY, super::A64_JIT_HOT_THRESHOLD - 1);
        assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
        assert_eq!(
            (cpu.pc, cpu.insn_count, cpu.jit.bounded_runs),
            (ENTRY + 4, 1, 0)
        );
        cpu.pc = ENTRY;
        cpu.sysregs.el1.cpacr = 3 << 20;
        cpu.jit.hot.insert(ENTRY, super::A64_JIT_HOT_THRESHOLD - 1);
        cpu.step_system().unwrap();
        assert_eq!(
            (
                cpu.sysregs.el1.elr,
                cpu.sysregs.el1.esr >> 26,
                cpu.insn_count,
                cpu.jit.bounded_runs
            ),
            (ENTRY, 0x19, 1, 0)
        );
    }
}

#[test]
fn represented_reserved_fields_keep_the_direct_undefined_exit_before_permissions() {
    for case in reserved_cases() {
        let word = case["word"].as_u64().unwrap() as u32;
        let zen = case["zen"].as_u64().unwrap();
        let mut cpu = cpu(word, 1);
        cpu.sysregs.el1.cpacr = (zen << 16) | (3 << 20);
        let before = (cpu.x, cpu.v, cpu.sve_p, cpu.sve_ffr, cpu.pstate_bits());
        let result = cpu.step();
        assert!(
            matches!(result, Ok(CpuExit::Undefined(raw)) if raw == word),
            "{case}: {result:?}"
        );
        assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (ENTRY, 0, 0));
        assert_eq!(
            (cpu.x, cpu.v, cpu.sve_p, cpu.sve_ffr, cpu.pstate_bits()),
            before
        );
    }
}

fn reserved_cases() -> Vec<serde_json::Value> {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a64-sve-access/reserved-oracle-cases.json"
    )))
    .unwrap()
}

#[test]
fn reserved_fields_deliver_the_independent_oracles_undefined_exception() {
    let cases = reserved_cases();
    assert_eq!(cases.len(), 40);
    for case in cases {
        let word = case["word"].as_u64().unwrap() as u32;
        let zen = case["zen"].as_u64().unwrap();
        let mut cpu = cpu(word, 1);
        cpu.sysregs.el1.cpacr = (zen << 16) | (3 << 20);
        cpu.step_system().unwrap();
        assert_eq!(u64::from(cpu.current_el), case["target"].as_u64().unwrap());
        assert_eq!(
            cpu.sysregs.el1.esr >> 26,
            case["ec"].as_u64().unwrap(),
            "{case}"
        );
        assert_eq!(
            cpu.sysregs.el1.esr & 0x1ff_ffff,
            case["iss"].as_u64().unwrap()
        );
        assert_eq!((cpu.sysregs.el1.elr, cpu.insn_count), (ENTRY, 0));
    }
}

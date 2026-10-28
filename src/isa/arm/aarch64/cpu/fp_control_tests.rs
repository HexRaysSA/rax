use super::*;
use crate::isa::arm::common::memory::FlatMemory;

const SYSREG_WORDS: [u32; 4] = [0xd53b_4400, 0xd53b_4420, 0xd51b_4400, 0xd51b_4420];

fn cptr(cpu: &mut AArch64Cpu, op1: u8, value: u64) {
    cpu.sysregs
        .impl_defined
        .insert(Aarch64SysRegEncoding::new(3, op1, 1, 1, 2).encode(), value);
}

fn configured(word: u32, el: u8, fpen: u64) -> AArch64Cpu {
    let mut config = AArch64Config::v8_2();
    config.features |= ArmFeatures::VHE;
    config.initial_el = el;
    config.gic_config = None;
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x5000)));
    cpu.pc = 0x100;
    cpu.sp_sel = el != 0;
    cpu.x.fill(0xdead);
    cpu.fpcr = 0x0040_0000;
    cpu.fpsr = 0x0800_0001;
    cpu.sysregs.scr_el3 = 0x501;
    cpu.sysregs.hcr_el2 = 1 << 31;
    cpu.sysregs.el1.cpacr = fpen << 20;
    cpu.sysregs.el1.vbar = 0x1000;
    cpu.sysregs.el2.vbar = 0x2000;
    cpu.sysregs.el3.vbar = 0x3000;
    cptr(&mut cpu, 4, 0);
    cptr(&mut cpu, 6, 0);
    cpu.write_memory(0x100, &word.to_le_bytes()).unwrap();
    cpu
}

#[test]
fn fp_sysreg_all_registers_observe_fpen_before_read_write_and_retirement() {
    for el in [0, 1] {
        for fpen in 0..4 {
            for base in SYSREG_WORDS {
                for rt in 0..32 {
                    let word = base | rt;
                    let mut cpu = configured(word, el, fpen);
                    let before = (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.pstate_bits());
                    let allowed = fpen == 3 || (el == 1 && fpen == 1);
                    let result = cpu.step();
                    if allowed {
                        assert_eq!(result.unwrap(), CpuExit::Continue, "{word:08x}");
                        assert_eq!((cpu.pc, cpu.insn_count), (0x104, 1));
                        if base & (1 << 21) != 0 {
                            assert_eq!(
                                cpu.get_x(rt as u8),
                                if rt == 31 {
                                    0
                                } else if base & 32 == 0 {
                                    0x0040_0000
                                } else {
                                    0x0800_0001
                                }
                            );
                            assert_eq!((cpu.fpcr, cpu.fpsr), (before.2, before.3));
                        } else {
                            assert_eq!(cpu.x, before.0);
                        }
                    } else {
                        assert!(
                            matches!(
                                result,
                                Err(ArmError::ArchitecturalException {
                                    ec: 7,
                                    iss: 0,
                                    target_el: None
                                })
                            ),
                            "{word:08x} EL{el} FPEN{fpen}"
                        );
                        assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (0x100, 0, 0));
                        assert_eq!(
                            (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.pstate_bits()),
                            before
                        );
                        // Host register inspection/replacement bypasses guest access controls.
                        assert_eq!(cpu.fpcr_value(), 0x0040_0000);
                        cpu.set_fpcr_value(0);
                        assert_eq!(cpu.fpcr_value(), 0);
                    }
                }
            }
        }
    }
}

#[test]
fn fp_sysreg_local_higher_and_vhe_traps_preserve_priority_and_target() {
    const RW: u64 = 1 << 31;
    const E2H: u64 = 1 << 34;
    const TGE: u64 = 1 << 27;
    const TFP: u64 = 1 << 10;
    // Explicit accessibility outcomes from Arm 102530_0002_05_en.
    let profiles = [
        (0, 0, RW, TFP, TFP, Some((1, 7))),
        (1, 0, RW, TFP, TFP, Some((1, 7))),
        (0, 0, RW | TGE, TFP, TFP, Some((2, 0))),
        (1, 0, RW | TGE, TFP, TFP, Some((1, 7))),
        (1, 3, RW, TFP, TFP, Some((2, 7))),
        (1, 3, RW, 0, TFP, Some((3, 7))),
        (2, 3, RW, TFP, 0, Some((2, 7))),
        (3, 3, RW, 0, TFP, Some((3, 7))),
        (0, 0, RW | E2H | TGE, 3 << 20, 0, None),
        (0, 3, RW | E2H | TGE, 1 << 20, 0, Some((2, 7))),
        (2, 3, RW | E2H, 0, 0, Some((2, 7))),
        (1, 3, RW | E2H, 1 << 20, 0, None),
        (2, 0, RW | E2H, 1 << 20, 0, None),
        // A direct synthetic EL1/TGE state is not a reachable ERET target.
        // Its data/system distinction is nevertheless specified separately.
        (1, 3, RW | E2H | TGE, 0, 0, Some((2, 7))),
    ];
    for (el, fpen, hcr, cp2, cp3, expected) in profiles {
        for word in SYSREG_WORDS {
            let mut cpu = configured(word, el, fpen);
            cpu.sysregs.hcr_el2 = hcr;
            cptr(&mut cpu, 4, cp2);
            cptr(&mut cpu, 6, cp3);
            assert!(cpu.fp_access_controls().have_el3);
            let before = (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.pstate_bits());
            match expected {
                None => assert_eq!(cpu.step().unwrap(), CpuExit::Continue),
                Some((target, ec)) => {
                    let error = cpu.step().unwrap_err();
                    assert_eq!(
                        error,
                        ArmError::ArchitecturalException {
                            ec,
                            iss: 0,
                            target_el: (target != 1).then_some(target)
                        }
                    );
                    assert_eq!(cpu.pc, 0x100);
                    assert_eq!(
                        (cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.pstate_bits()),
                        before
                    );
                    cpu.deliver_fault(error).unwrap();
                    assert_eq!(cpu.current_el, target);
                    assert_eq!(cpu.sysregs.bank(target).elr, 0x100);
                    assert_eq!(
                        cpu.sysregs.bank(target).esr,
                        (u64::from(ec) << 26) | (1 << 25)
                    );
                    assert_eq!(cpu.sysregs.bank(target).spsr, before.4);
                    assert_eq!(cpu.insn_count, 0);
                }
            }
        }
    }
}

#[test]
fn fp_data_and_system_access_follow_the_pinned_higher_control_rule() {
    for (word, denied) in [(0x1e22_2820u32, true), (0xd53b_4400, true)] {
        let mut cpu = configured(word, 1, 3);
        cpu.sysregs.hcr_el2 = (1 << 31) | (1 << 34) | (1 << 27);
        cptr(&mut cpu, 4, 0);
        let result = cpu.step();
        if denied {
            assert!(matches!(
                result,
                Err(ArmError::ArchitecturalException {
                    ec: 7,
                    target_el: Some(2),
                    ..
                })
            ));
            assert_eq!(cpu.insn_count, 0);
        } else {
            assert_eq!(result.unwrap(), CpuExit::Continue);
            assert_eq!(cpu.insn_count, 1);
        }
    }
}

#[test]
fn fp_sysreg_illegal_state_has_priority_over_access_checks() {
    let mut cpu = configured(SYSREG_WORDS[0], 1, 0);
    cpu.il = true;
    assert!(matches!(
        cpu.step(),
        Err(ArmError::ArchitecturalException { ec: 0x0e, .. })
    ));
    assert_eq!((cpu.pc, cpu.insn_count), (0x100, 0));
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn cached_fp_sysreg_access_survives_dead_result_optimization() {
    for (name, instruction) in [
        ("fpcr_xzr", 0xd53b_441f),
        ("fpsr_xzr", 0xd53b_443f),
        ("fpcr_overwritten_x9", 0xd53b_4409),
        ("fpsr_overwritten_x9", 0xd53b_4429),
    ] {
        let mut cpu = AArch64Cpu::new(
            AArch64Config {
                gic_config: None,
                ..Default::default()
            },
            Box::new(FlatMemory::new(0, 0x4000)),
        );
        let code = [
            0x9100_0400u32, // ADD X0,X0,#1
            instruction,
            0xd280_0029, // MOV X9,#1: discard the MRS result
            0xf100_081f, // CMP X0,#2
            0x54ff_ff83, // B.LO entry
            0xd420_0000, // BRK native frontier
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
        cpu.write_memory(0x1000, &code).unwrap();
        cpu.pc = 0x1000;
        cpu.current_el = 1;
        cpu.sp_sel = true;
        cpu.sysregs.el1.cpacr = 3 << 20;
        let Some(region) = cpu.jit_compile_region() else {
            // These existing X9-write shapes may be outside native clobber
            // admission. The confirmed XZR native controls must remain runnable.
            assert!(
                name.contains("overwritten_x9"),
                "{name}: lost native admission"
            );
            cpu.sysregs.el1.cpacr = 0;
            assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
            assert_eq!((cpu.pc, cpu.x[0], cpu.insn_count), (0x1004, 1, 1));
            assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
            assert_eq!(
                (
                    cpu.sysregs.el1.elr,
                    cpu.sysregs.el1.esr >> 26,
                    cpu.insn_count
                ),
                (0x1004, 7, 1)
            );
            continue;
        };
        assert!(
            region.fp_access.system,
            "{name}: source permission must survive optimization"
        );
        cpu.sysregs.el1.cpacr = 0;
        let before = (cpu.pc, cpu.x, cpu.fpcr, cpu.fpsr);
        let ran = cpu.jit_run_region(&region);
        eprintln!(
            "case={name} optimized_uses_fp={} denied_native_ran={ran}",
            region.uses_fp
        );
        assert!(
            !ran,
            "{name}: optimized-away access must still require permission"
        );
        assert_eq!((cpu.pc, cpu.x, cpu.fpcr, cpu.fpsr), before);
        assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
        assert_eq!((cpu.pc, cpu.x[0], cpu.insn_count), (0x1004, 1, 1));
        assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
        assert_eq!(
            (
                cpu.sysregs.el1.elr,
                cpu.sysregs.el1.esr >> 26,
                cpu.insn_count
            ),
            (0x1004, 7, 1)
        );
    }
}

#[test]
fn fp_sysreg_higher_controls_follow_security_and_implemented_vhe() {
    let mut secure = configured(SYSREG_WORDS[0], 0, 3);
    secure.sysregs.scr_el3 = 1 << 10;
    cptr(&mut secure, 4, 1 << 10);
    assert!(!secure.fp_access_controls().el2_enabled);
    assert_eq!(secure.step().unwrap(), CpuExit::Continue);

    let mut no_vhe = configured(SYSREG_WORDS[0], 0, 3);
    no_vhe.config.features.remove(ArmFeatures::VHE);
    no_vhe.sysregs.hcr_el2 = (1 << 31) | (1 << 34) | (1 << 27);
    cptr(&mut no_vhe, 4, 0);
    assert_eq!(no_vhe.step().unwrap(), CpuExit::Continue);
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn fp_sysreg_cached_and_cold_admission_follow_higher_control_transitions() {
    use std::sync::Arc;
    for word in SYSREG_WORDS {
        let word = word | 31;
        let mut cpu = configured(word, 1, 3);
        let code = [0x9100_0400u32, word, 0xf100_081f, 0x54ff_ffa3, 0xd420_0000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        cpu.write_memory(0x1000, &code).unwrap();
        cpu.pc = 0x1000;
        cpu.x[0] = 0;
        let Some(compiled) = cpu.jit_compile_region() else {
            assert_eq!(
                word & (1 << 21),
                0,
                "MRS XZR native admission lost: {word:08x}"
            );
            cptr(&mut cpu, 4, 1 << 10);
            assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
            assert_eq!((cpu.pc, cpu.x[0], cpu.insn_count), (0x1004, 1, 1));
            assert_eq!(cpu.step_system().unwrap(), CpuExit::Continue);
            assert_eq!(
                (
                    cpu.sysregs.el2.elr,
                    cpu.sysregs.el2.esr >> 26,
                    cpu.insn_count
                ),
                (0x1004, 7, 1)
            );
            continue;
        };
        let region = Arc::new(compiled);
        assert!(region.fp_access.system);
        let enabled = (0x1000, cpu.jit_mode_tag());
        cpu.jit.cache.insert(enabled, Some(region.clone()));
        for (hcr, cp2, cp3) in [
            (1 << 31, 1 << 10, 0),
            (1 << 31, 0, 1 << 10),
            ((1 << 31) | (1 << 34), 0, 0),
        ] {
            cpu.pc = 0x1000;
            cpu.x[0] = 0;
            cpu.sysregs.hcr_el2 = hcr;
            cptr(&mut cpu, 4, cp2);
            cptr(&mut cpu, 6, cp3);
            let before = (cpu.pc, cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.insn_count);
            assert!(!cpu.jit_run_region(&region));
            assert_eq!(
                (cpu.pc, cpu.x, cpu.v, cpu.fpcr, cpu.fpsr, cpu.insn_count),
                before
            );
            assert!(cpu.jit_lookup(0x1000).is_none());
            assert!(cpu.jit_compile_region().is_none());
            let denied = (0x1000, cpu.jit_mode_tag());
            cpu.jit.cache.insert(denied, None);
            cpu.sysregs.hcr_el2 = 1 << 31;
            cptr(&mut cpu, 4, 0);
            cptr(&mut cpu, 6, 0);
            assert_eq!((0x1000, cpu.jit_mode_tag()), enabled);
            assert!(Arc::ptr_eq(&cpu.jit_lookup(0x1000).unwrap(), &region));
            assert!(cpu.jit_run_region(&region));
            assert_eq!((cpu.pc, cpu.x[0]), (0x1010, 2));
        }
    }
}

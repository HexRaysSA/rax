//! Selected optional FP profile: precise status, routing, state bridge and native frontier.
use super::*;
use crate::isa::arm::common::memory::FlatMemory;

fn configured(word: u32, el: u8) -> AArch64Cpu {
    let mut config = AArch64Config::v8_2();
    config.initial_el = el;
    config.gic_config = None;
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x5000)));
    cpu.pc = 0x100;
    cpu.sp_sel = el != 0;
    cpu.sysregs.scr_el3 = 0x501;
    cpu.sysregs.hcr_el2 = 1 << 31;
    cpu.sysregs.el1.cpacr = 3 << 20;
    cpu.sysregs.el1.vbar = 0x1000;
    cpu.sysregs.el2.vbar = 0x2000;
    cpu.sysregs.el3.vbar = 0x3000;
    let id = cpu.sysregs.aarch32_fp_ids()[0] | (1 << 12);
    cpu.sysregs.impl_defined.insert(
        Aarch64SysRegEncoding::new(3, 0, 0, 3, 0).encode(),
        u64::from(id),
    );
    cpu.write_memory(0x100, &word.to_le_bytes()).unwrap();
    cpu
}

#[test]
fn scalar_all_precisions_and_el_targets_keep_fault_pc_destinations_and_retirement() {
    for word in [0x1ee21820, 0x1e221820, 0x1e621820] {
        // FDIV H/S/D0,1,2: zero/zero
        for el in 0..=3 {
            for tge in [false, true] {
                let mut cpu = configured(word, el);
                if tge {
                    cpu.sysregs.hcr_el2 |= 1 << 27;
                }
                cpu.fpcr = 0x100;
                cpu.fpsr = 0x08000001; // an already-sticky cause must still trap
                cpu.v[0] = 0xdeadbeef;
                let before = (
                    cpu.x,
                    cpu.v,
                    cpu.nzcv,
                    cpu.sve_p,
                    cpu.sve_ffr,
                    cpu.pstate_bits(),
                );
                let error = cpu.step().unwrap_err();
                let target = if el > 1 {
                    el
                } else if tge {
                    2
                } else {
                    1
                };
                assert_eq!(
                    error,
                    ArmError::ArchitecturalException {
                        ec: 0x2c,
                        iss: 0x800001,
                        target_el: Some(target)
                    },
                    "word={word:08x} EL{el} TGE={tge}"
                );
                assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (0x100, 0, 0));
                assert_eq!(
                    (
                        cpu.x,
                        cpu.v,
                        cpu.nzcv,
                        cpu.sve_p,
                        cpu.sve_ffr,
                        cpu.pstate_bits()
                    ),
                    before
                );
                assert_eq!((cpu.fpcr, cpu.fpsr), (0x100, 0x08000001));
                cpu.deliver_fault(error).unwrap();
                let bank = cpu.sysregs.bank(target);
                assert_eq!(
                    (bank.elr, bank.esr, bank.spsr),
                    (0x100, (0x2c << 26) | (1 << 25) | 0x800001, before.5)
                );
            }
        }
    }
}

#[test]
fn a64_combined_flags_preserve_unenabled_sticky_status_and_transfer_controls() {
    for enables in [0x400, 0x1000, 0x1400, 0x100] {
        let mut cpu = configured(0x1e220820, 1); // FMUL S0,S1,S2
        cpu.v[1] = 0x7f7fffff;
        cpu.v[2] = 0x40000000;
        cpu.v[0] = 0x12345678;
        cpu.fpcr = enables;
        cpu.fpsr = 0x08000002;
        let result = cpu.step();
        if enables & 0x1400 != 0 {
            assert!(
                matches!(
                    result,
                    Err(ArmError::ArchitecturalException {
                        ec: 0x2c,
                        iss,
                        ..
                    }) if iss == (0x800000 | (0x14 & (enables >> 8)))
                ),
                "{result:?}"
            );
            assert_eq!(cpu.v[0], 0x12345678);
            assert_eq!(cpu.fpsr, 0x08000002 | (0x14 & !(enables >> 8)));
        } else {
            assert_eq!(result.unwrap(), CpuExit::Continue);
            assert_eq!(cpu.fpsr, 0x08000016);
        }
    }
    let mut cpu = configured(0xd51b4400, 1); // MSR FPCR,X0
    cpu.x[0] = u64::MAX;
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.fpcr_value(), 0x07c89f07);
    cpu.pc = 0x100;
    cpu.write_memory(0x100, &0xd53b4401u32.to_le_bytes())
        .unwrap();
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
    assert_eq!(cpu.x[1], 0x07c89f07);
}

#[test]
fn mixed_width_fp_status_and_enables_survive_a64_exception_delivery() {
    use crate::isa::arm::aarch64::aarch32_state::Aarch32Pstate;
    for thumb in [false, true] {
        for tge in [false, true] {
            let mut cpu = configured(0, 0);
            cpu.aarch32 = Aarch32Pstate::from_spsr(0x10 | if thumb { 1 << 5 } else { 0 });
            if tge {
                cpu.sysregs.hcr_el2 |= 1 << 27;
            }
            let raw = 0xee210a02u32; // VMUL.F32 S0,S2,S4
            let bytes = if thumb {
                [0x21, 0xee, 0x02, 0x0a]
            } else {
                raw.to_le_bytes()
            };
            cpu.write_memory(0x100, &bytes).unwrap();
            cpu.v[0] = 0x12345678 | (0x7f7fffffu128 << 64);
            cpu.v[1] = 0x40000000;
            cpu.fpcr = 0x400;
            cpu.fpsr = 2;
            let before = cpu.v;
            let error = cpu.step().unwrap_err();
            assert_eq!(
                error,
                ArmError::ArchitecturalException {
                    ec: 0x28,
                    iss: 0x800704,
                    target_el: Some(if tge { 2 } else { 1 })
                }
            );
            assert_eq!((cpu.pc, cpu.insn_count, cpu.cycle_count), (0x100, 0, 0));
            assert_eq!(cpu.v, before);
            assert_eq!((cpu.fpcr, cpu.fpsr), (0x400, 0x12));
            assert!(cpu.aarch32.is_some());
            cpu.deliver_fault(error).unwrap();
            let bank = cpu.sysregs.bank(if tge { 2 } else { 1 });
            assert_eq!(bank.elr, 0x100);
            assert_eq!(bank.esr, (0x28 << 26) | (1 << 25) | 0x800704);
        }
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn previously_compiled_native_region_cannot_bypass_selected_fp_traps() {
    let mut cpu = configured(0x91000400, 1);
    let code = [0x91000400u32, 0xf100081f, 0x54ffffc3, 0xd4200000]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    cpu.write_memory(0x100, &code).unwrap();
    let region = cpu
        .jit_compile_region()
        .expect("integer native control must compile");
    cpu.fpcr = 0x100;
    let before = (cpu.pc, cpu.x, cpu.v, cpu.insn_count);
    assert!(!cpu.jit_run_region(&region));
    assert_eq!((cpu.pc, cpu.x, cpu.v, cpu.insn_count), before);
    assert!(cpu.jit_compile_region().is_none());
    assert_eq!(cpu.step_system_bounded(true).unwrap(), CpuExit::Continue);
    assert_eq!((cpu.pc, cpu.x[0], cpu.insn_count), (0x104, 1, 1));
}

#[test]
fn simd_and_sve_collect_only_executed_lanes_and_restore_destinations() {
    for sve in [false, true] {
        for active in [false, true] {
            if !sve && !active {
                continue;
            }
            let word = if sve { 0x65988000 } else { 0x4e22d420 };
            let mut cpu = configured(word, 1);
            cpu.config.features |= ArmFeatures::SVE;
            cpu.sysregs.el1.cpacr |= 3 << 16;
            cpu.sysregs
                .impl_defined
                .insert(Aarch64SysRegEncoding::new(3, 6, 1, 1, 2).encode(), 1 << 8);
            cpu.fpcr = 0x100;
            cpu.v[0] = 0x7f800001u128 << 96;
            cpu.v[1] = cpu.v[0];
            cpu.sve_p[0] = if active { 0xffff } else { 0 };
            let before = (cpu.v, cpu.sve_p, cpu.sve_ffr, cpu.x, cpu.nzcv);
            let result = cpu.step();
            if active {
                assert!(
                    matches!(
                        result,
                        Err(ArmError::ArchitecturalException {
                            ec: 0x2c,
                            iss: 0x800001,
                            ..
                        })
                    ),
                    "SVE={sve} {result:?}"
                );
                assert_eq!((cpu.v, cpu.sve_p, cpu.sve_ffr, cpu.x, cpu.nzcv), before);
                assert_eq!((cpu.pc, cpu.insn_count), (0x100, 0));
            } else {
                assert_eq!(result.unwrap(), CpuExit::Continue);
                assert_eq!(cpu.fpsr & 0x9f, 0);
                assert_eq!(cpu.v, before.0);
            }
        }
    }
}

#[test]
fn underflow_controls_distinguish_exact_tiny_from_output_flushing_in_all_precisions() {
    for (word, lhs, rhs, precision) in [
        (0x1ee20820, 0x0400u128, 0x3800u128, 16),
        (0x1e220820, 0x00800000, 0x3f000000, 32),
        (0x1e620820, 0x0010000000000000, 0x3fe0000000000000, 64),
    ] {
        for fz in [false, true] {
            for fz16 in [false, true] {
                let mut cpu = configured(word, 1);
                cpu.v[0] = 0xdeadbeef;
                cpu.v[1] = lhs;
                cpu.v[2] = rhs;
                cpu.fpcr = 0x800 | u32::from(fz) << 24 | u32::from(fz16) << 19;
                let result = cpu.step();
                if if precision == 16 { fz16 } else { fz } {
                    assert_eq!(result.unwrap(), CpuExit::Continue);
                    assert_eq!(cpu.v[0], 0);
                    assert_eq!(cpu.fpsr, 8);
                } else {
                    assert!(
                        matches!(
                            result,
                            Err(ArmError::ArchitecturalException {
                                ec: 0x2c,
                                iss: 0x800008,
                                ..
                            })
                        ),
                        "precision={precision} FZ={fz} FZ16={fz16} {result:?}"
                    );
                    assert_eq!(cpu.v[0], 0xdeadbeef);
                    assert_eq!(cpu.fpsr, 0);
                    assert_eq!((cpu.pc, cpu.insn_count), (0x100, 0));
                }
            }
        }
    }
}

#[test]
fn selected_a64_fpexc_alias_ignores_tfv_writes_and_rejects_el1() {
    let encoding = Aarch64SysRegEncoding::new(3, 4, 5, 3, 0);
    for vectors in [false, true] {
        let mut cpu = configured(0, 2);
        if vectors {
            let id = cpu.sysregs.aarch32_fp_ids()[0] | 1 << 24;
            cpu.sysregs.impl_defined.insert(
                Aarch64SysRegEncoding::new(3, 0, 0, 3, 0).encode(),
                u64::from(id),
            );
        }
        cpu.write_sysreg(encoding, u64::MAX).unwrap();
        assert_eq!(
            cpu.read_sysreg(encoding).unwrap(),
            if vectors { 0x6000079f } else { 0x6400079f }
        );
        cpu.write_sysreg(encoding, 1 << 30).unwrap();
        assert_eq!(
            cpu.read_sysreg(encoding).unwrap(),
            if vectors { 0x40000700 } else { 0x44000700 }
        );
        cpu.current_el = 1;
        assert!(matches!(
            cpu.read_sysreg(encoding),
            Err(ArmError::InvalidExceptionLevel(1))
        ));
        assert!(matches!(
            cpu.write_sysreg(encoding, 0),
            Err(ArmError::InvalidExceptionLevel(1))
        ));
    }
}

#[test]
fn exact_sve_scaling_and_half_simd_use_the_same_typed_underflow_boundary() {
    // LLVM: FSCALE Z0.D,P0/M,Z0.D,Z1.D; FMUL V0.8H,V1.8H,V2.8H.
    for sve in [false, true] {
        for enabled in [false, true] {
            let mut cpu = configured(if sve { 0x65c98020 } else { 0x6e421c20 }, 1);
            cpu.config.features |= ArmFeatures::SVE;
            cpu.sysregs.el1.cpacr |= 3 << 16;
            cpu.sysregs
                .impl_defined
                .insert(Aarch64SysRegEncoding::new(3, 6, 1, 1, 2).encode(), 1 << 8);
            cpu.fpcr = if enabled { 0x800 } else { 0 };
            if sve {
                cpu.v[0] = 0x0010000000000000;
                cpu.v[1] = u64::MAX as u128;
                cpu.sve_p[0] = 1;
            } else {
                cpu.v[0] = 0xdeadbeef;
                cpu.v[1] = 0x0400;
                cpu.v[2] = 0x3800;
            }
            let before = cpu.v;
            let result = cpu.step();
            if enabled {
                assert!(
                    matches!(
                        result,
                        Err(ArmError::ArchitecturalException {
                            ec: 0x2c,
                            iss: 0x800008,
                            ..
                        })
                    ),
                    "SVE={sve} {result:?}"
                );
                assert_eq!(cpu.v, before);
                assert_eq!(cpu.fpsr, 0);
            } else {
                assert_eq!(result.unwrap(), CpuExit::Continue);
                assert_eq!(cpu.v[0], if sve { 0x0008000000000000 } else { 0x0200 });
                assert_eq!(cpu.fpsr, 0, "exact scaling/multiplication is not inexact");
            }
        }
    }
}

#[test]
fn half_precision_conversion_ignores_fz16_for_its_exact_tiny_output() {
    for fz16 in [false, true] {
        let mut cpu = configured(0x1e23c020, 1); // FCVT H0,S1
        cpu.v[0] = 0xdeadbeef;
        cpu.v[1] = 0x35800000; // 2^-20, exactly representable in binary16
        cpu.fpcr = 0x800 | u32::from(fz16) << 19;
        assert!(matches!(
            cpu.step(),
            Err(ArmError::ArchitecturalException {
                ec: 0x2c,
                iss: 0x800008,
                ..
            })
        ));
        assert_eq!(cpu.v[0], 0xdeadbeef);
        assert_eq!(cpu.fpsr, 0);
    }
}

//! Mixed-width exception return and execution. Register aliases follow Arm's
//! LookUpRIndex table; expectations below do not call the implementation map.

use super::pauth_keyed::keyed_cpu;
use super::*;
use crate::isa::arm::aarch64::pauth::{PauthAlgorithm, PauthKeyKind, PauthProfile};

#[path = "pauth_aarch32_smir.rs"]
mod smir;

const MODES: [(u8, usize); 8] = [
    (0x10, 13),
    (0x11, 29),
    (0x12, 17),
    (0x13, 19),
    (0x17, 21),
    (0x1b, 23),
    (0x1f, 13),
    (0x1a, 15),
];

fn prepare(
    raw: u32,
    mode: u8,
    thumb: bool,
    algorithm: PauthAlgorithm,
    profile: PauthProfile,
) -> AArch64Cpu {
    let mut cpu = keyed_cpu(raw, algorithm, profile);
    cpu.current_el = match mode {
        0x10 => 1,
        0x1a => 3,
        _ => 2,
    };
    if cpu.current_el == 2 {
        cpu.sysregs.hcr_el2 &= !(1 << 31);
    }
    if cpu.current_el == 3 {
        cpu.sysregs.scr_el3 &= !(1 << 10);
    }
    cpu.sysregs.bank_mut(cpu.current_el).sctlr = (1 << 31) | (1 << 30);
    cpu.sysregs.bank_mut(cpu.current_el).tcr = 16 | (16 << 16);
    cpu.sp_el = [0x4000, 0x5000, 0x6000, 0x7000];
    for index in 0..31 {
        cpu.x[index] = 0xa100_0000_0000_0800 | index as u64 * 16;
    }
    cpu.x[1] = 0xa200_0000_0000_0042;
    for index in 0..32 {
        cpu.v[index] = u128::from(index as u64 + 1) * 0x1234_5678_9abc_def0;
    }
    cpu.fpcr = 0x07c0_0000;
    cpu.fpsr = 0x8800_009f;
    let target = 0x1_0000_0103;
    let signed = if raw == 0xd69f_03e0 {
        target
    } else {
        cpu.pauth_value(
            target,
            cpu.current_sp(),
            if raw == 0xd69f_0fff {
                PauthKeyKind::Ib
            } else {
                PauthKeyKind::Ia
            },
            false,
            true,
        )
        .unwrap()
    };
    let bank = cpu.sysregs.bank_mut(cpu.current_el);
    bank.elr = signed;
    bank.spsr = 0xa800_0000 | (5 << 16) | (7 << 6) | u64::from(thumb) << 5 | u64::from(mode);
    if thumb {
        cpu.memory.write(0x102, &0x4608u16.to_le_bytes()).unwrap(); // MOV R0,R1
        cpu.memory.write(0x104, &0xb001u16.to_le_bytes()).unwrap(); // ADD SP,#4
    } else {
        cpu.memory.write_u32(0x100, 0xe1a0_0001).unwrap(); // MOV R0,R1
        cpu.memory.write_u32(0x104, 0xe28d_d004).unwrap(); // ADD SP,SP,#4
    }
    cpu
}

#[test]
fn pauth_eret_aarch32_handoff_executes_arm_and_thumb_in_every_legal_bank() {
    let mut cases = 0;
    for algorithm in [PauthAlgorithm::Qarma3, PauthAlgorithm::Qarma5] {
        for profile in [
            PauthProfile::Base,
            PauthProfile::Pauth2,
            PauthProfile::Fpac,
            PauthProfile::FpacCombine,
        ] {
            for raw in [0xd69f_03e0, 0xd69f_0bff, 0xd69f_0fff] {
                for (mode, sp_index) in MODES {
                    for thumb in [false, true] {
                        let mut cpu = prepare(raw, mode, thumb, algorithm, profile);
                        let x = cpu.x;
                        let sp_banks = cpu.sp_el;
                        let v = cpu.v;
                        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
                        assert_eq!(
                            cpu.pstate_bits(),
                            0xa805_01c0 | u64::from(thumb) << 5 | u64::from(mode),
                            "{algorithm:?} {profile:?} {raw:#x} {mode:#x}"
                        );
                        assert_eq!(cpu.pc, if thumb { 0x102 } else { 0x100 });
                        assert_eq!(cpu.current_sp(), u64::from(x[sp_index] as u32));
                        assert_eq!(cpu.x, x);
                        cpu.step().unwrap();
                        assert_eq!(cpu.x[0], 0xa100_0000_0000_0042);
                        cpu.step().unwrap();
                        assert_eq!(cpu.x[sp_index], x[sp_index] + 4);
                        assert_eq!(cpu.current_sp(), u64::from(x[sp_index] as u32) + 4);
                        assert_eq!(cpu.sp_el, sp_banks);
                        assert_eq!(cpu.v, v);
                        assert_eq!(cpu.fpcr, 0x07c0_0000);
                        assert_eq!(cpu.fpsr, 0x8800_009f);
                        assert_eq!(cpu.insn_count, 3);
                        cases += 1;
                    }
                }
            }
        }
    }
    assert_eq!(cases, 384);
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn pauth_eret_aarch32_actual_native_handoff_matches_direct_and_continues() {
    let mut cases = 0;
    for raw in [0xd69f_0bff, 0xd69f_0fff] {
        for (mode, _) in MODES {
            for thumb in [false, true] {
                let make = || {
                    prepare(
                        raw,
                        mode,
                        thumb,
                        PauthAlgorithm::Qarma5,
                        PauthProfile::FpacCombine,
                    )
                };
                let mut direct = make();
                direct.jit.disabled = true;
                let mut native = make();
                let region =
                    std::sync::Arc::new(native.jit_compile_region().expect("compile ERETAA/B"));
                native
                    .jit
                    .cache
                    .insert((0, native.jit_mode_tag()), Some(region));
                for _ in 0..3 {
                    assert_eq!(
                        direct.step_system_with_fault_exit().unwrap(),
                        CpuExit::Continue
                    );
                    assert_eq!(
                        native.step_system_with_fault_exit().unwrap(),
                        CpuExit::Continue
                    );
                    assert_eq!(native.x, direct.x);
                    assert_eq!(native.sp_el, direct.sp_el);
                    assert_eq!(native.pc, direct.pc);
                    assert_eq!(native.pstate_bits(), direct.pstate_bits());
                    assert_eq!(native.v, direct.v);
                    assert_eq!(native.insn_count, direct.insn_count);
                    assert_eq!(
                        crate::codec::serialize(&native.export_sregs()).unwrap(),
                        crate::codec::serialize(&direct.export_sregs()).unwrap()
                    );
                }
                assert_eq!(native.jit.pauth_native_runs, 1);
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 32);
}

#[test]
fn pauth_eret_aarch32_fpaccombine_fault_precedes_width_and_bank_transition() {
    for profile in [
        PauthProfile::Base,
        PauthProfile::Pauth2,
        PauthProfile::Fpac,
        PauthProfile::FpacCombine,
    ] {
        for (raw, iss) in [(0xd69f_0bff, 0), (0xd69f_0fff, 1)] {
            let mut cpu = prepare(raw, 0x11, false, PauthAlgorithm::Qarma5, profile);
            cpu.sysregs.el2.elr ^= 1 << 48;
            let saved = cpu.pstate_bits();
            let registers = cpu.x;
            let sp = cpu.sp_el;
            if profile == PauthProfile::FpacCombine {
                assert!(
                    matches!(cpu.step(), Err(ArmError::ArchitecturalException { ec: 0x1c, iss: actual, .. }) if actual == iss)
                );
                assert_eq!(cpu.pc, 0);
                assert_eq!(cpu.pstate_bits(), saved);
                assert_eq!(cpu.x, registers);
                assert_eq!(cpu.sp_el, sp);
                assert_eq!(cpu.insn_count, 0);
            } else {
                // Arm ERET authenticates before the AArch32 address truncation.
                // Poison outside [31:0] is discarded; only FPACCOMBINE gives
                // this combined instruction a synchronous authentication fault.
                cpu.step().unwrap();
                assert_eq!(cpu.pc, 0x100);
                assert_eq!(cpu.aarch32.unwrap().mode, 0x11);
                assert_eq!(cpu.insn_count, 1);
            }
        }
    }
}

#[test]
fn pauth_eret_aarch32_svc_enters_aarch64_and_authenticated_handler_returns() {
    for thumb in [false, true] {
        let mut cpu = prepare(
            0xd69f_0bff,
            0x10,
            thumb,
            PauthAlgorithm::Qarma5,
            PauthProfile::FpacCombine,
        );
        let entry = if thumb { 0x102 } else { 0x100 };
        if thumb {
            cpu.memory.write(entry, &0xdf42u16.to_le_bytes()).unwrap();
        } else {
            cpu.memory.write_u32(entry, 0xef00_0042).unwrap();
        }
        cpu.sysregs.el1.vbar = 0x1000;
        for (index, raw) in [0xd538_4022u32, 0xdac1_03e2, 0xd518_4022, 0xd69f_0bff]
            .into_iter()
            .enumerate()
        {
            cpu.memory
                .write_u32(0x1600 + index as u64 * 4, raw)
                .unwrap();
        }
        cpu.step_system_with_fault_exit().unwrap();
        let saved = cpu.pstate_bits();
        cpu.step_system_with_fault_exit().unwrap();
        assert_eq!(cpu.pc, 0x1600);
        assert!(cpu.aarch32.is_none());
        assert_eq!(cpu.current_el, 1);
        assert_eq!(cpu.sysregs.el1.spsr, saved);
        assert_eq!(cpu.sysregs.el1.elr, entry + if thumb { 2 } else { 4 });
        assert_eq!(
            cpu.sysregs.el1.esr,
            (0x11 << 26) | (u64::from(!thumb) << 25) | 0x42
        );
        for _ in 0..4 {
            cpu.step_system_with_fault_exit().unwrap();
        }
        assert_eq!(cpu.pstate_bits(), saved);
        assert_eq!(cpu.pc, entry + if thumb { 2 } else { 4 });
        assert_eq!(cpu.current_el, 0);
        assert_eq!(cpu.insn_count, 6);
    }
}

#[test]
fn pauth_eret_aarch32_handler_uses_svc_and_undef_banks_instead_of_a64_vectors() {
    for (word, vector, lr, spsr_bank) in [
        (0xef00_0042, 8, 0x104, None),
        (0xe7f0_00f0, 4, 0x104, Some(2)),
    ] {
        let mut cpu = prepare(
            0xd69f_0fff,
            0x10,
            false,
            PauthAlgorithm::Qarma3,
            PauthProfile::FpacCombine,
        );
        cpu.step().unwrap();
        cpu.sysregs.hcr_el2 &= !(1 << 31);
        cpu.sysregs.el1.sctlr = 0;
        cpu.sysregs.el1.vbar = 0x2000;
        cpu.memory.write_u32(0x100, word).unwrap();
        cpu.dit = true;
        let saved = (cpu.pstate_bits() & !((1 << 24) | (1 << 21))) | (1 << 21);
        cpu.step_system().unwrap();
        let mode = if spsr_bank.is_some() { 0x1b } else { 0x13 };
        assert_eq!(cpu.aarch32.unwrap().mode, mode);
        assert_eq!(cpu.pc, 0x2000 + vector);
        assert_eq!(cpu.get_lr() as u32, lr);
        assert_eq!(cpu.current_el, 1);
        assert!(cpu.pan);
        let actual = if let Some(bank) = spsr_bank {
            cpu.sysregs.impl_defined[&Aarch64SysRegEncoding::new(3, 4, 4, 3, bank).encode()]
        } else {
            cpu.sysregs.el1.spsr
        };
        assert_eq!(actual, saved);
    }
}

#[test]
fn pauth_eret_aarch32_fp_aliases_and_disabled_fp_trap_preserve_unshared_vectors() {
    for allowed in [false, true] {
        let mut cpu = prepare(
            0xd69f_0bff,
            0x10,
            false,
            PauthAlgorithm::Qarma5,
            PauthProfile::FpacCombine,
        );
        cpu.step().unwrap();
        cpu.v[0] = u128::from(1.25f64.to_bits()) | (u128::from(2.5f64.to_bits()) << 64);
        cpu.sysregs.el1.cpacr = if allowed { 3 << 20 } else { 0 };
        cpu.memory.write_u32(0x100, 0xee70_0b01).unwrap(); // VADD.F64 D16,D0,D1
        let before = cpu.v;
        if allowed {
            cpu.step().unwrap();
            let mut expected = before;
            expected[8] = (expected[8] & (!0u128 << 64)) | u128::from(3.75f64.to_bits());
            assert_eq!(cpu.v, expected);
            assert_eq!(cpu.pc, 0x104);
        } else {
            assert!(matches!(
                cpu.step(),
                Err(ArmError::ArchitecturalException {
                    ec: 7,
                    target_el: Some(1),
                    ..
                })
            ));
            assert_eq!(cpu.pc, 0x100);
            assert_eq!(cpu.v, before);
            assert_eq!(cpu.insn_count, 1);
        }
    }
}

#[test]
fn pauth_eret_aarch32_saved_state_checks_width_controls_and_banked_sp() {
    use crate::smir::ir::context::Aarch64RegState;
    use crate::vm::vcpu::{Aarch64CpuState, Aarch64Registers};
    for (mode, sp_register) in MODES {
        let mut cpu = prepare(
            0xd69f_0bff,
            mode,
            true,
            PauthAlgorithm::Qarma5,
            PauthProfile::FpacCombine,
        );
        cpu.step().unwrap();
        let state = Aarch64CpuState {
            regs: Aarch64Registers {
                x: cpu.x,
                sp: cpu.current_sp(),
                pc: cpu.pc,
                pstate: cpu.pstate_bits(),
                v: std::array::from_fn(|i| [cpu.v[i] as u64, (cpu.v[i] >> 64) as u64]),
                fpcr: cpu.fpcr,
                fpsr: cpu.fpsr,
            },
            sregs: cpu.export_sregs(),
        };
        AArch64Cpu::validate_saved_state(state.regs.pstate, &state.sregs).unwrap();
        let mut ir = Aarch64RegState::from_cpu_state(&state).unwrap();
        ir.set_sp_value(0x1234);
        let exported = ir.to_cpu_state().unwrap();
        assert_eq!(exported.regs.sp, 0x1234);
        assert_eq!(
            exported.regs.x[sp_register],
            (cpu.x[sp_register] & !0xffff_ffff) | 0x1234
        );
        assert_eq!(exported.sregs.sp_el0, state.sregs.sp_el0);
        assert_eq!(exported.sregs.sp_el1, state.sregs.sp_el1);
        let mut missing = state.sregs.clone();
        missing.execution = None;
        assert!(AArch64Cpu::validate_saved_state(state.regs.pstate, &missing).is_err());
        let mut no_a32 = state.sregs.clone();
        no_a32.execution.as_mut().unwrap().sysregs.id_aa64pfr0_el1 = 0x1111;
        assert!(AArch64Cpu::validate_saved_state(state.regs.pstate, &no_a32).is_err());
    }
}

#[test]
fn pauth_eret_aarch32_it_restore_normalizes_reserved_and_itd_cases() {
    use crate::isa::arm::aarch64::aarch32_state::{Aarch32Pstate, return_pstate};
    let cpu = prepare(
        0xd69f_0bff,
        0x10,
        true,
        PauthAlgorithm::Qarma5,
        PauthProfile::FpacCombine,
    );
    let mut count = 0;
    for it in 0..=255u8 {
        for thumb in [false, true] {
            for illegal in [false, true] {
                for itd in [false, true] {
                    let mut controls = cpu.pauth_controls();
                    controls.sctlr[1] = u64::from(itd) << 7;
                    let saved = 0x10
                        | (u64::from(thumb) << 5)
                        | (u64::from(illegal) << 20)
                        | (u64::from(it & 3) << 25)
                        | (u64::from(it >> 2) << 10)
                        | (1 << 24)
                        | (1 << 23)
                        | (1 << 22)
                        | (1 << 27)
                        | (15 << 16);
                    let restored = return_pstate(saved, true, controls).unwrap();
                    let expected_it = if illegal
                        || (thumb && (it == 0 || it & 15 != 0) && (!itd || it & 7 == 0))
                    {
                        it
                    } else {
                        0
                    };
                    let state = Aarch32Pstate::from_spsr(restored).unwrap();
                    assert_eq!(
                        state.it, expected_it,
                        "IT={it:#x} T={thumb} IL={illegal} ITD={itd}"
                    );
                    assert_eq!(state.t, thumb);
                    assert_eq!(state.ge, 15);
                    assert!(state.q);
                    assert_eq!(restored & ((7 << 22) | (1 << 21)), (7 << 22) | (1 << 21));
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 2048);
}

#[test]
fn pauth_eret_aarch32_unsupported_planes_preserve_the_exact_frontier() {
    for translation in [false, true] {
        let mut cpu = prepare(
            0xd69f_0bff,
            0x13,
            false,
            PauthAlgorithm::Qarma5,
            PauthProfile::FpacCombine,
        );
        cpu.step().unwrap();
        if translation {
            cpu.sysregs.el1.sctlr |= 1;
            cpu.update_mmu_config();
        } else {
            // MRC p15,0,R0,c0,c0,0: do not expose the v7 snapshot's default MIDR.
            cpu.memory.write_u32(0x100, 0xee10_0f10).unwrap();
        }
        let registers = cpu.x;
        let pstate = cpu.pstate_bits();
        let spsr = cpu.sysregs.el1.spsr;
        assert!(matches!(
            cpu.step_system(),
            Err(ArmError::UnsupportedExecutionState(_))
        ));
        assert_eq!(cpu.pc, 0x100);
        assert_eq!(cpu.x, registers);
        assert_eq!(cpu.pstate_bits(), pstate);
        assert_eq!(cpu.sysregs.el1.spsr, spsr);
        assert_eq!(cpu.insn_count, 1);
    }
}

#[test]
fn pauth_eret_aarch32_exclusive_monitor_survives_steps_and_observes_global_failure() {
    let mut count = 0;
    for (load, store, width, status) in [
        (0xe1d1_2f9f, 0xe1c1_3f94, 1, 3),
        (0xe1f1_2f9f, 0xe1e1_3f94, 2, 3),
        (0xe191_2f9f, 0xe181_3f94, 4, 3),
        (0xe1b1_2f9f, 0xe1a1_6f94, 8, 6),
    ] {
        for big_endian in [false, true] {
            for invalidate in [0, 1, 2] {
                let mut cpu = prepare(
                    0xd69f_0fff,
                    0x10,
                    false,
                    PauthAlgorithm::Qarma5,
                    PauthProfile::FpacCombine,
                );
                cpu.sysregs.el1.spsr |= u64::from(big_endian) << 9;
                cpu.step().unwrap();
                cpu.x[1] = 0x800;
                cpu.x[4] = 0x1020_3040;
                cpu.x[5] = 0x5060_7080;
                cpu.memory
                    .write(0x800, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
                    .unwrap();
                cpu.memory.write_u32(0x100, load).unwrap();
                cpu.memory
                    .write_u32(
                        0x104,
                        if invalidate == 2 {
                            0xf57f_f01f
                        } else {
                            0xe1a0_0000
                        },
                    )
                    .unwrap();
                cpu.memory.write_u32(0x108, store).unwrap();
                cpu.step().unwrap();
                let initial = if big_endian { 0x1122_3344 } else { 0x4433_2211 };
                let expected_read = match width {
                    1 => 0x11,
                    2 => {
                        if big_endian {
                            0x1122
                        } else {
                            0x2211
                        }
                    }
                    _ => initial,
                };
                assert_eq!(cpu.x[2] as u32, expected_read);
                if width == 8 {
                    assert_eq!(
                        cpu.x[3] as u32,
                        if big_endian { 0x5566_7788 } else { 0x8877_6655 }
                    );
                }
                cpu.step().unwrap();
                if invalidate == 1 {
                    cpu.memory.clear_exclusive();
                }
                cpu.step().unwrap();
                assert_eq!(
                    cpu.x[status] as u32,
                    u32::from(invalidate != 0),
                    "width={width} BE={big_endian} invalidate={invalidate}"
                );
                let bytes = cpu.read_memory(0x800, 8).unwrap();
                let mut expected = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
                if invalidate == 0 {
                    let value = if width == 8 {
                        if big_endian {
                            0x1020_3040_5060_7080u64
                        } else {
                            0x5060_7080_1020_3040
                        }
                    } else {
                        0x1020_3040
                    };
                    let encoded = if big_endian {
                        value.to_be_bytes()
                    } else {
                        value.to_le_bytes()
                    };
                    let source = if big_endian {
                        &encoded[8 - width..]
                    } else {
                        &encoded[..width]
                    };
                    expected[..width].copy_from_slice(source);
                }
                assert_eq!(
                    bytes, expected,
                    "width={width} BE={big_endian} invalidate={invalidate}"
                );
                count += 1;
            }
        }
    }
    assert_eq!(count, 24);
}

#[test]
fn pauth_eret_aarch32_reset_clears_reservation_before_a64_store_exclusive() {
    let mut cpu = prepare(
        0xd69f_0bff,
        0x10,
        false,
        PauthAlgorithm::Qarma5,
        PauthProfile::FpacCombine,
    );
    cpu.step().unwrap();
    cpu.set_x(1, 0x800);
    cpu.memory.write_u64(0x800, 0x1122_3344_5566_7788).unwrap();
    cpu.memory.write_u32(0x100, 0xe1b1_2f9f).unwrap(); // LDREXD R2,R3,[R1]
    cpu.step().unwrap();
    cpu.reset();
    assert!(cpu.aarch32.is_none());
    cpu.set_x(1, 0x800);
    cpu.set_x(3, 0xaabb_ccdd_eeff_0011);
    cpu.memory.write_u32(0, 0xc802_7c23).unwrap(); // STXR W2,X3,[X1]
    cpu.step().unwrap();
    assert_eq!(cpu.get_x(2), 1);
    assert_eq!(cpu.memory.read_u64(0x800).unwrap(), 0x1122_3344_5566_7788);
    assert_eq!(cpu.insn_count, 1);
}

#[test]
fn pauth_eret_aarch32_illegal_execution_uses_the_destination_handler_width() {
    for (mode, expected_ec, handler) in [
        (0x10, 0x0e, 0x2600),
        (0x13, 0, 0xffff_0004),
        (0x1a, 0x0e, 0x2004),
    ] {
        let mut cpu = prepare(
            0xd69f_0bff,
            mode,
            false,
            PauthAlgorithm::Qarma5,
            PauthProfile::FpacCombine,
        );
        cpu.sysregs.bank_mut(cpu.current_el).spsr |= 1 << 20;
        cpu.step().unwrap();
        let target = cpu.current_el.max(1);
        cpu.sysregs.bank_mut(target).vbar = 0x2000;
        cpu.sysregs.bank_mut(target).esr = 0x1234;
        let before = cpu.x;
        assert!(
            matches!(cpu.step(), Err(ArmError::ArchitecturalException { ec, iss: 0, target_el: Some(el) }) if ec == expected_ec && el == target)
        );
        assert_eq!(cpu.x, before);
        assert_eq!(cpu.pc, 0x100);
        assert_eq!(cpu.insn_count, 1);
        cpu.step_system().unwrap();
        // The A64 setup's EnDB bit 13 is SCTLR.V at AArch32 EL1.
        assert_eq!(cpu.pc, handler);
        if mode == 0x13 {
            assert_eq!(cpu.sysregs.el1.esr, 0x1234);
            assert_eq!(cpu.aarch32.unwrap().mode, 0x1b);
        } else {
            assert_eq!(
                cpu.sysregs.bank(target).esr,
                (u64::from(expected_ec) << 26) | (1 << 25)
            );
        }
        assert_eq!(cpu.insn_count, 1);
    }
}

#[test]
fn pauth_eret_aarch32_abort_uses_dfsr_ifsr_and_the_correct_far_half() {
    use crate::isa::arm::common::cpu::{AccessType, MemoryFaultInfo, MemoryFaultType};
    let mut cases = 0;
    for (fault_type, short_section, short_page, long_base) in [
        (MemoryFaultType::Translation, 5, 7, 4),
        (MemoryFaultType::AccessFlag, 3, 6, 8),
        (MemoryFaultType::Permission, 13, 15, 12),
        (MemoryFaultType::Alignment, 1, 1, 0x21),
        (MemoryFaultType::SyncExternal, 8, 8, 0x10),
        (MemoryFaultType::TlbConflict, 0x10, 0x10, 0x30),
    ] {
        for long in [false, true] {
            for level in [1, 2] {
                for access in [
                    AccessType::Read,
                    AccessType::Write,
                    AccessType::InstructionFetch,
                ] {
                    let mut cpu = prepare(
                        0xd69f_0bff,
                        0x13,
                        false,
                        PauthAlgorithm::Qarma5,
                        PauthProfile::FpacCombine,
                    );
                    cpu.step().unwrap();
                    cpu.sysregs.el1.sctlr = 0;
                    cpu.sysregs.el1.tcr = u64::from(long) << 31;
                    cpu.sysregs.el1.vbar = 0x2000;
                    cpu.sysregs.el1.far = 0x1234_5678_8765_4321;
                    cpu.sysregs.el1.esr = 0x1234;
                    let ifsr = Aarch64SysRegEncoding::new(3, 4, 5, 0, 1).encode();
                    cpu.sysregs.impl_defined.insert(ifsr, 0x5678);
                    cpu.last_fault_level
                        .store(level, std::sync::atomic::Ordering::Relaxed);
                    let saved =
                        (cpu.pstate_bits() & !((1 << 24) | (1 << 21))) | (u64::from(cpu.dit) << 21);
                    cpu.deliver_fault(ArmError::MemoryError(MemoryFaultInfo {
                        address: 0xabc0,
                        access,
                        fault_type,
                        stage2: false,
                    }))
                    .unwrap();
                    let code = if long {
                        (1 << 9) | long_base | if long_base < 16 { u64::from(level) } else { 0 }
                    } else {
                        let code = if level == 1 {
                            short_section
                        } else {
                            short_page
                        };
                        ((code & 16) << 6) | (code & 15)
                    };
                    if access == AccessType::InstructionFetch {
                        assert_eq!(cpu.sysregs.impl_defined[&ifsr], code);
                        assert_eq!(cpu.sysregs.el1.esr, 0x1234);
                        assert_eq!(cpu.sysregs.el1.far, 0x0000_abc0_8765_4321);
                        assert_eq!(cpu.pc, 0x200c);
                        assert_eq!(cpu.get_lr() as u32, 0x104);
                    } else {
                        assert_eq!(
                            cpu.sysregs.el1.esr,
                            code | (u64::from(access == AccessType::Write) << 11)
                        );
                        assert_eq!(cpu.sysregs.impl_defined[&ifsr], 0x5678);
                        assert_eq!(cpu.sysregs.el1.far, 0x1234_5678_0000_abc0);
                        assert_eq!(cpu.pc, 0x2010);
                        assert_eq!(cpu.get_lr() as u32, 0x108);
                    }
                    assert_eq!(
                        cpu.sysregs.impl_defined
                            [&Aarch64SysRegEncoding::new(3, 4, 4, 3, 1).encode()],
                        saved
                    );
                    assert_eq!(cpu.aarch32.unwrap().mode, 0x17);
                    assert_eq!(cpu.insn_count, 1);
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 72);
}

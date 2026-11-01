//! Selected synchronous support-code boundary for restricted scalar VFP modes.
use rax::isa::arm::aarch32::vfp::Fpscr;
use rax::isa::arm::decoder::{Aarch32Decoder, ThumbDecoder};
use rax::isa::arm::execution::{ArmMemory, FlatMemory};
use rax::isa::arm::{Armv7Cpu, ExceptionType, ExecResult, Executor};
use serde::Deserialize;

#[derive(Deserialize)]
struct Cases {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    rounding: String,
    nan: serde_json::Value,
    flush: String,
    kind: String,
    arm: u32,
    thumb: u32,
}

fn cases() -> Vec<Case> {
    serde_json::from_str::<Cases>(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/development/a32-restricted-fp/cases.json"
    )))
    .unwrap()
    .cases
}

fn controls(index: u32) -> u32 {
    (index & 3) << 22
        | ((index >> 2) & 1) << 25
        | ((index >> 3) & 1) << 24
        | ((index >> 4) & 1) << 19
        | ((index >> 5) & 1) << 26
}

fn configured(thumb: bool, support: u32, control: u32) -> Armv7Cpu {
    let mut cpu = Armv7Cpu::new();
    cpu.cpsr.t = thumb;
    cpu.regs = std::array::from_fn(|index| 0x1122_3300 + index as u32);
    cpu.regs[0] = 0x800;
    cpu.regs[1] = control;
    cpu.regs[15] = 0x100;
    cpu.vfp.dregs.fill(0x3ff0_0000_3f80_0000);
    cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !(15 << 28)) | ((support & 1) << 28);
    cpu.vfp.mvfr1 = (cpu.vfp.mvfr1 & !0xff) | (((support >> 1) & 1) << 4) | ((support >> 2) & 1);
    cpu.vfp.fpscr = Fpscr::from_bits(0xa800_009f | control);
    cpu
}

fn execute(cpu: &mut Armv7Cpu, case: &Case, memory: &mut FlatMemory) -> ExecResult {
    let insn = if cpu.cpsr.t {
        ThumbDecoder::decode_32bit(case.thumb)
    } else {
        Aarch32Decoder::decode(case.arm)
    }
    .unwrap();
    Executor::new(cpu, memory).execute(&insn)
}

// The table records instruction control dependencies from the retained Arm
// pseudocode. This applies the selected synchronous subarchitecture to that
// independent table; no production admission helper supplies expectations.
fn supported(case: &Case, support: u32, control: u32) -> bool {
    let round = support & 1 != 0
        || match case.rounding.as_str() {
            "none" | "nearest" | "convert_zero" => true,
            "fpscr" => control & (3 << 22) == 0,
            "away" | "plus" | "minus" | "zero" => false,
            other => panic!("unknown fixture rounding {other}"),
        };
    let needs_nan = case.nan == true || case.nan == "unless_ahp" && control & (1 << 26) == 0;
    let nan = !needs_nan || support & 2 != 0 || control & (1 << 25) != 0;
    let flush = support & 4 != 0
        || match case.flush.as_str() {
            "none" => true,
            "base" => control & (1 << 24) != 0,
            "half" => control & (1 << 19) != 0,
            other => panic!("unknown fixture flush dependency {other}"),
        };
    round && nan && flush
}

#[test]
fn scalar_mode_matrix_preserves_the_unsupported_instruction_frontier() {
    let cases = cases();
    let mut denied = 0;
    let mut completed = 0;
    for thumb in [false, true] {
        for support in 0..8 {
            for index in 0..64 {
                let control = controls(index);
                for case in cases.iter().filter(|case| case.kind == "scalar") {
                    let mut cpu = configured(thumb, support, control);
                    let before = serde_json::to_vec(&cpu).unwrap();
                    let mut memory = FlatMemory::new(4096, 0);
                    let result = execute(&mut cpu, case, &mut memory);
                    if supported(case, support, control) {
                        assert!(
                            matches!(result, ExecResult::Continue),
                            "{} thumb={thumb} support={support} control={control:#x}: {result:?}",
                            case.name
                        );
                        completed += 1;
                    } else {
                        assert!(
                            matches!(
                                result,
                                ExecResult::Exception(ExceptionType::UndefinedInstruction)
                            ),
                            "{} thumb={thumb} support={support} control={control:#x}: {result:?}",
                            case.name
                        );
                        assert_eq!(
                            serde_json::to_vec(&cpu).unwrap(),
                            before,
                            "{} thumb={thumb} support={support} control={control:#x}",
                            case.name
                        );
                        assert_eq!(memory.read_word(0x800).unwrap(), 0);
                        denied += 1;
                    }
                }
            }
        }
    }
    assert_eq!(denied + completed, 138_240);
    assert!(denied > 0 && completed > 0);
    eprintln!("scalar mode matrix: {completed} completed, {denied} precise bounces");
}

#[test]
fn restricted_vfp_controls_do_not_disable_storage_or_advanced_simd() {
    for thumb in [false, true] {
        for case in cases().iter().filter(|case| case.kind == "independent") {
            let mut cpu = configured(thumb, 0, 3 << 22);
            let mut memory = FlatMemory::new(4096, 0);
            let result = execute(&mut cpu, case, &mut memory);
            assert!(
                matches!(result, ExecResult::Continue),
                "{} thumb={thumb}: {result:?}",
                case.name
            );
        }
    }
}

#[test]
fn restricted_capabilities_do_not_force_guest_fpscr_writes_or_reads() {
    let cases = cases();
    let write = cases.iter().find(|case| case.name == "vmsr").unwrap();
    let read = cases.iter().find(|case| case.name == "vmrs").unwrap();
    for thumb in [false, true] {
        for index in 0..64 {
            let value = 0xa800_009f | controls(index);
            let mut cpu = configured(thumb, 0, 0);
            let mut memory = FlatMemory::new(4096, 0);
            cpu.regs[1] = value;
            assert!(matches!(
                execute(&mut cpu, write, &mut memory),
                ExecResult::Continue
            ));
            assert_eq!(cpu.vfp.fpscr.bits(), value);
            assert!(matches!(
                execute(&mut cpu, read, &mut memory),
                ExecResult::Continue
            ));
            assert_eq!(cpu.regs[1], value);
        }
    }
}

#[test]
fn reserved_scalar_control_capabilities_precede_access_traps() {
    let cases = cases();
    let add = cases.iter().find(|case| case.name == "vadd_f32").unwrap();
    for thumb in [false, true] {
        for field in 0..3 {
            for reserved in 2..16 {
                let mut cpu = super::hyp();
                cpu.cpsr.t = thumb;
                cpu.cp15.hcptr = 1 << 10;
                match field {
                    0 => cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !(15 << 28)) | (reserved << 28),
                    1 => cpu.vfp.mvfr1 = (cpu.vfp.mvfr1 & !0xf0) | (reserved << 4),
                    2 => cpu.vfp.mvfr1 = (cpu.vfp.mvfr1 & !15) | reserved,
                    _ => unreachable!(),
                }
                let before = (
                    cpu.regs,
                    cpu.vfp.dregs,
                    cpu.vfp.fpscr.bits(),
                    cpu.cpsr.to_u32(),
                );
                let mut memory = FlatMemory::new(4096, 0);
                let result = execute(&mut cpu, add, &mut memory);
                assert!(
                    matches!(result, ExecResult::Undefined),
                    "field={field} value={reserved} thumb={thumb}: {result:?}"
                );
                assert_eq!(
                    (
                        cpu.regs,
                        cpu.vfp.dregs,
                        cpu.vfp.fpscr.bits(),
                        cpu.cpsr.to_u32()
                    ),
                    before
                );
            }
        }
    }
}

#[test]
fn access_traps_precede_the_selected_runtime_support_code_bounce() {
    let cases = cases();
    let add = cases.iter().find(|case| case.name == "vadd_f32").unwrap();
    for thumb in [false, true] {
        let mut cpu = super::hyp();
        cpu.cpsr.t = thumb;
        cpu.cp15.hcptr = 1 << 10;
        cpu.vfp.mvfr0 &= !(15 << 28);
        cpu.vfp.mvfr1 &= !0xff;
        cpu.vfp.fpscr = Fpscr::from_bits(3 << 22);
        let before = cpu.vfp.dregs;
        let result = execute(&mut cpu, add, &mut FlatMemory::new(4096, 0));
        assert!(
            matches!(
                result,
                ExecResult::FpAccessTrap {
                    target_el: 2,
                    undefined: true,
                    ..
                }
            ),
            "{result:?}"
        );
        assert_eq!(cpu.vfp.dregs, before);
    }
}

#[test]
fn failed_arm_predicate_suppresses_the_runtime_mode_check() {
    let mut cpu = configured(false, 0, 3 << 22);
    cpu.cpsr.z = true;
    let before = (
        cpu.regs,
        cpu.vfp.dregs,
        cpu.vfp.fpscr.bits(),
        cpu.cpsr.to_u32(),
    );
    let insn = Aarch32Decoder::decode(0x1e31_0a02).unwrap(); // VADDNE.F32 S0,S2,S4.
    let result = Executor::new(&mut cpu, &mut FlatMemory::new(4096, 0)).execute(&insn);
    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(
        (
            cpu.regs,
            cpu.vfp.dregs,
            cpu.vfp.fpscr.bits(),
            cpu.cpsr.to_u32()
        ),
        before
    );
}

#[test]
fn failed_thumb_predicate_suppresses_the_runtime_mode_check() {
    let mut cpu = configured(true, 0, 3 << 22);
    cpu.cpsr.z = true;
    cpu.cpsr.it_state = 0x18; // IT NE fails with Z=1.
    let before = serde_json::to_vec(&cpu).unwrap();
    let insn = ThumbDecoder::decode_32bit(0xee31_0a02).unwrap();
    let result = Executor::new(&mut cpu, &mut FlatMemory::new(4096, 0)).execute(&insn);
    assert!(matches!(result, ExecResult::Continue));
    assert_eq!(serde_json::to_vec(&cpu).unwrap(), before);
}

#[test]
fn scalar_capability_reserved_values_do_not_disable_independent_operations() {
    for thumb in [false, true] {
        for case in cases().iter().filter(|case| case.kind == "independent") {
            let mut cpu = configured(thumb, 0, 3 << 22);
            cpu.vfp.mvfr0 |= 15 << 28;
            cpu.vfp.mvfr1 |= 0xff;
            let result = execute(&mut cpu, case, &mut FlatMemory::new(4096, 0));
            assert!(
                matches!(result, ExecResult::Continue),
                "{} thumb={thumb}: {result:?}",
                case.name
            );
        }
    }
}

#[test]
fn aarch32_lifter_retains_the_scalar_fp_interpreter_frontier() {
    use rax::smir::ir::types::SourceArch;
    use rax::smir::lift::aarch32::Aarch32Lifter;
    use rax::smir::lift::{LiftContext, LiftError, SmirLifter};
    for case in cases()
        .iter()
        .filter(|case| case.kind == "scalar" || case.name == "vmrs_fpsid")
    {
        let mut context = LiftContext::new(SourceArch::Aarch32);
        let result = Aarch32Lifter::new().lift_insn(0x100, &case.arm.to_le_bytes(), &mut context);
        assert!(
            matches!(result, Err(LiftError::Unsupported { .. })),
            "{}: {result:?}",
            case.name
        );
    }
}

#[test]
fn restricted_profiles_advertise_the_selected_support_code_subarchitecture() {
    let cases = cases();
    let read = cases.iter().find(|case| case.name == "vmrs_fpsid").unwrap();
    for thumb in [false, true] {
        for support in 0..8 {
            for raw in [0x4103_3070, 0x1234_5678, u32::MAX] {
                for index in 0..64 {
                    let mut cpu = configured(thumb, support, controls(index));
                    cpu.vfp.fpsid = raw;
                    let expected = if support == 7 {
                        raw
                    } else {
                        (raw & !0x007f_0000) | 0x0040_0000
                    };
                    let mut memory = FlatMemory::new(4096, 0);
                    assert!(matches!(
                        execute(&mut cpu, read, &mut memory),
                        ExecResult::Continue
                    ));
                    assert_eq!(
                        cpu.regs[0], expected,
                        "thumb={thumb} support={support} raw={raw:#x} control={index}"
                    );
                    assert_eq!(cpu.vfp.fpsid, raw);
                    assert!(format!("{:?}", cpu.vfp).contains(&format!("FPSID: {expected:08x}")));
                    assert_eq!(cpu.vfp.fpscr.bits(), 0xa800_009f | controls(index));
                }
            }
        }
    }
}

#[test]
fn mixed_width_profile_identity_and_restricted_modes_share_the_same_capabilities() {
    use rax::isa::arm::aarch64::AArch64Cpu;
    use rax::isa::arm::common::cpu::{ArmCpu, ArmError, CpuExit};
    use rax::isa::arm::common::sysreg::Aarch64SysRegEncoding;

    fn registers(cpu: &AArch64Cpu) -> Vec<u8> {
        let core: [u64; 31] = std::array::from_fn(|index| cpu.get_x(index as u8));
        let simd: [u128; 32] = std::array::from_fn(|index| cpu.get_simd(index as u8));
        serde_json::to_vec(&(
            cpu.export_sregs(),
            core,
            simd,
            cpu.fpcr_value(),
            cpu.fpsr_value(),
            cpu.get_pc(),
            cpu.pstate_bits(),
            cpu.instruction_count(),
        ))
        .unwrap()
    }

    for thumb in [false, true] {
        for support in 0..8 {
            for trapped in [false, true] {
                let mut cpu = super::mixed(super::VADD, thumb, 2, false, true);
                let mut state = cpu.export_sregs();
                let system = &mut state.execution.as_mut().unwrap().sysregs;
                system
                    .impl_defined
                    .insert(Aarch64SysRegEncoding::new(3, 4, 1, 1, 2).encode(), 0);
                let vfp = configured(thumb, support, 0).vfp;
                for (index, value) in [vfp.mvfr0, vfp.mvfr1, vfp.mvfr2].into_iter().enumerate() {
                    system.impl_defined.insert(
                        Aarch64SysRegEncoding::new(3, 0, 0, 3, index as u8).encode(),
                        u64::from(value),
                    );
                }
                cpu.import_sregs(&state).unwrap();
                cpu.set_fpcr_value(1 << 22);
                cpu.set_fpsr_value(0xa800_009f);
                let encode = |word: u32| {
                    if thumb {
                        [
                            ((word >> 16) as u16).to_le_bytes(),
                            (word as u16).to_le_bytes(),
                        ]
                        .concat()
                    } else {
                        word.to_le_bytes().to_vec()
                    }
                };
                cpu.write_memory(0x100, &encode(0xeef0_0a10)).unwrap(); // LLVM VMRS R0,FPSID.
                cpu.write_memory(0x104, &encode(super::VADD)).unwrap();
                assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
                assert_eq!(
                    cpu.get_x(0),
                    if support == 7 {
                        0x4103_3070
                    } else {
                        0x4140_3070
                    }
                );
                assert_eq!(cpu.get_pc(), 0x104);
                assert_eq!(cpu.instruction_count(), 1);
                if trapped {
                    let mut state = cpu.export_sregs();
                    state
                        .execution
                        .as_mut()
                        .unwrap()
                        .sysregs
                        .impl_defined
                        .insert(Aarch64SysRegEncoding::new(3, 4, 1, 1, 2).encode(), 1 << 10);
                    cpu.import_sregs(&state).unwrap();
                }
                let before = registers(&cpu);
                let result = cpu.step();
                if trapped {
                    assert!(
                        matches!(
                            result,
                            Err(ArmError::ArchitecturalException {
                                ec: 7,
                                target_el: Some(2),
                                ..
                            })
                        ),
                        "support={support} thumb={thumb}: {result:?}"
                    );
                    assert_eq!(registers(&cpu), before);
                } else if support != 7 {
                    assert!(
                        matches!(result, Err(ArmError::UndefinedInstruction(actual)) if actual == super::VADD),
                        "support={support} thumb={thumb}: {result:?}"
                    );
                    assert_eq!(registers(&cpu), before);
                } else {
                    assert_eq!(result.unwrap(), CpuExit::Continue);
                    assert_eq!(cpu.get_simd(0) as u32, 0x4040_0000);
                    assert_eq!(cpu.get_pc(), 0x108);
                    assert_eq!(cpu.instruction_count(), 2);
                }
            }
        }
    }
}

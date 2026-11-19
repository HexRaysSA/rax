//! Scalar FP16 predicate constraints in the retained Arm A32/T32 encodings.
use super::*;
use rax::isa::arm::common::ArmFeatures;
use rax::isa::arm::decoder::ThumbDecoder;

const COMPARE: u32 = 0xeeb4_0941; // VCMP.F16 S0,S2.

fn a32_word(raw: u32, thumb: bool, predicated: bool) -> u32 {
    if !thumb && predicated {
        raw & 0x0fff_ffff // EQ
    } else {
        raw
    }
}

fn run(raw: u32, thumb: bool, predicate_passes: Option<bool>, trap: bool) -> (ExecResult, bool) {
    let raw = a32_word(raw, thumb, predicate_passes.is_some());
    let insn = if thumb {
        ThumbDecoder::decode_32bit(raw)
    } else {
        Aarch32Decoder::decode(raw)
    }
    .unwrap();
    let mut cpu = if trap { hyp() } else { Armv7Cpu::new() };
    if trap {
        cpu.cp15.hcptr = 1 << 10;
    }
    cpu.cpsr.t = thumb;
    if let Some(z) = predicate_passes {
        cpu.cpsr.z = z;
        if thumb {
            cpu.cpsr.set_it_state(0, 8); // IT EQ
        }
    }
    cpu.regs[0] = 0x1234_0001;
    cpu.vfp.write_s_bits(0, 0x3f80_3c00);
    cpu.vfp.write_s_bits(2, 0x3f00_3800);
    cpu.vfp.write_s_bits(4, 0x4000_4000);
    let before = (cpu.regs, cpu.vfp.dregs, cpu.vfp.fpscr.bits());
    let result = Executor::new(&mut cpu, &mut Memory32::new(4096, 0)).execute(&insn);
    let modified = before != (cpu.regs, cpu.vfp.dregs, cpu.vfp.fpscr.bits());
    (result, modified)
}

#[test]
fn scalar_half_predicate_compare_does_not_update_fpscr() {
    for thumb in [false, true] {
        let (result, modified) = run(COMPARE, thumb, Some(true), false);
        assert!(
            matches!(result, ExecResult::Undefined) && !modified,
            "Thumb={thumb}, result={result:?}, modified={modified}"
        );
    }
}

#[test]
fn scalar_half_predicate_rejects_before_fp_access() {
    let ordinary = [
        COMPARE,
        0xeeb5_0940, // VCMP.F16 S0,#0.
        0xeeb4_09c1, // VCMPE.F16 S0,S2.
        0xeeb5_09c0, // VCMPE.F16 S0,#0.
        0xee31_0902, // VADD.F16.
        0xee21_0942, // VNMUL.F16.
        0xeea1_0902, // VFMA.F16.
        0xeeb0_09c1, // VABS.F16.
        0xeeb1_09c1, // VSQRT.F16.
        0xeeb7_0900, // VMOV.F16 (immediate).
        0xee00_0910, // VMOV.F16 (core to scalar).
        0xee11_0910, // VMOV.F16 (scalar to core).
        0xeeb7_0941, // VRINTX.F16.
        0xeebd_09c1, // VCVT.S32.F16.
        0xeeb8_0941, // VCVT.F16.U32.
        0xeebe_09c8, // VCVT.S32.F16 (fixed-point).
    ];
    let unconditional_a32 = [
        0xfeb0_0a41, // VMOVX.F16.
        0xfeb0_0ac1, // VINS.F16.
        0xfe01_0902, // VSELEQ.F16.
        0xfe81_0902, // VMAXNM.F16.
        0xfeb8_0941, // VRINTA.F16.
        0xfebc_09c1, // VCVTA.S32.F16.
    ];
    for thumb in [false, true] {
        for raw in ordinary.into_iter().chain(unconditional_a32) {
            let (result, _) = run(raw, thumb, None, false);
            assert!(
                matches!(result, ExecResult::Continue),
                "{raw:08x} {result:?}"
            );
            if !thumb && unconditional_a32.contains(&raw) {
                continue; // The A32 unconditional namespace has no condition field.
            }
            for (passes, trap) in [(true, false), (true, true), (false, true)] {
                let (result, modified) = run(raw, thumb, Some(passes), trap);
                assert!(!modified, "{raw:08x}, Thumb={thumb}: {result:?}");
                assert!(
                    if passes {
                        matches!(result, ExecResult::Undefined)
                    } else {
                        matches!(result, ExecResult::Continue)
                    },
                    "{raw:08x}, Thumb={thumb}, passes={passes}, trap={trap}: {result:?}"
                );
            }
        }
    }
}

#[test]
fn scalar_half_predicate_retains_neighboring_conditional_operations() {
    for thumb in [false, true] {
        for raw in [
            0xeeb4_0a41, // VCMP.F32.
            0xeeb4_0b41, // VCMP.F64.
            0xeeb2_0a41, // VCVTB.F32.F16.
            0xeeb3_0bc1, // VCVTT.F16.F64.
        ] {
            let (result, modified) = run(raw, thumb, Some(true), false);
            assert!(
                matches!(result, ExecResult::Continue) && modified,
                "{raw:08x}"
            );
            let (result, modified) = run(raw, thumb, Some(false), true);
            assert!(
                matches!(result, ExecResult::Continue) && !modified,
                "{raw:08x}"
            );
            let (result, modified) = run(raw, thumb, Some(true), true);
            assert!(
                matches!(result, ExecResult::FpAccessTrap { target_el: 2, .. }) && !modified,
                "{raw:08x}: {result:?}"
            );
        }
    }
}

#[test]
fn scalar_half_predicate_precedes_mixed_width_el2_access_trap() {
    for thumb in [false, true] {
        for passes in [None, Some(false), Some(true)] {
            let raw = a32_word(COMPARE, thumb, passes.is_some());
            let mut cpu = mixed(raw, thumb, 2, false, true);
            let mut state = cpu.export_sregs();
            state.execution.as_mut().unwrap().features |= ArmFeatures::FP16.bits();
            cpu.import_sregs(&state).unwrap();
            let it_eq = if thumb && passes.is_some() {
                2 << 10
            } else {
                0
            };
            let z = u64::from(passes == Some(true)) << 30;
            let pstate = (0x1d3 | (u64::from(thumb) << 5)) | it_eq | z;
            cpu.set_pstate_bits(pstate).unwrap();
            let before = (cpu.get_simd(0), cpu.fpsr_value());
            let result = cpu.step();
            assert!(
                match passes {
                    None => matches!(
                        result,
                        Err(ArmError::ArchitecturalException {
                            ec: 7,
                            target_el: Some(2),
                            ..
                        })
                    ),
                    Some(false) => matches!(result, Ok(CpuExit::Continue)),
                    Some(true) =>
                        matches!(result, Err(ArmError::UndefinedInstruction(word)) if word == raw),
                },
                "Thumb={thumb}, passes={passes:?}: {result:?}"
            );
            let retired = u64::from(passes == Some(false));
            assert_eq!(cpu.get_pc(), 0x100 + 4 * retired);
            assert_eq!((cpu.get_simd(0), cpu.fpsr_value()), before);
            assert_eq!(cpu.instruction_count(), retired);
        }
    }
}

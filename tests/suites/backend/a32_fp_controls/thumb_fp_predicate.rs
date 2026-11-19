//! Thumb FP predicate restrictions in Arm DDI0597 ID032025.
use super::*;
use rax::isa::arm::common::ArmFeatures;
use rax::isa::arm::decoder::ThumbDecoder;

const SIMD_ADD_HALF: u32 = 0xef11_0d02;
const INPUT: [u64; 4] = [
    0x4040_0000_4000_0000,
    0x3f80_3c00_3f80_3c00,
    0x4000_3800_4000_3800,
    0x2000_2800_3000_3800,
];

type Effects = ([u32; 16], [u64; 32], u32);

fn run(raw: u32, predicate_passes: Option<bool>, trap: bool) -> (ExecResult, Effects, Effects) {
    let mut cpu = if trap { hyp() } else { Armv7Cpu::new() };
    if trap {
        cpu.cp15.hcptr = 1 << 10;
    }
    cpu.cp15.id_isar[5] |= 1 << 24; // RDM.
    cpu.cp15.id_isar6 |= 1 << 8; // FHM.
    cpu.cpsr.t = true;
    cpu.cpsr.z = predicate_passes.unwrap_or(true);
    if predicate_passes.is_some() {
        cpu.cpsr.set_it_state(0, 8); // IT EQ.
    }
    cpu.vfp.dregs[..INPUT.len()].copy_from_slice(&INPUT);
    let state = |cpu: &Armv7Cpu| (cpu.regs, cpu.vfp.dregs, cpu.vfp.fpscr.bits());
    let before = state(&cpu);
    let insn = ThumbDecoder::decode_32bit(raw).unwrap();
    let result = Executor::new(&mut cpu, &mut Memory32::new(4096, 0)).execute(&insn);
    (result, before, state(&cpu))
}

fn check_restricted(words: &[u32]) {
    for &raw in words {
        let (result, _, _) = run(raw, None, false);
        assert!(
            matches!(result, ExecResult::Continue),
            "{raw:08x}: {result:?}"
        );
        let (result, before, after) = run(raw, None, true);
        assert!(
            matches!(result, ExecResult::FpAccessTrap { target_el: 2, .. }),
            "{raw:08x}: {result:?}"
        );
        assert_eq!(after, before, "{raw:08x}");
        for (passes, trap) in [(true, false), (true, true), (false, true)] {
            let (result, before, after) = run(raw, Some(passes), trap);
            assert!(
                if passes {
                    matches!(result, ExecResult::Undefined)
                } else {
                    matches!(result, ExecResult::Continue)
                },
                "{raw:08x}, passes={passes}, trap={trap}: {result:?}"
            );
            assert_eq!(after, before, "{raw:08x}");
        }
    }
}

#[test]
fn thumb_fp_predicate_rejects_restricted_simd_encodings() {
    check_restricted(&[
        SIMD_ADD_HALF, // VADD.F16 (same-size arithmetic).
        0xff31_0d02,   // VABD.F16.
        0xef11_0c12,   // VFMA.F16.
        0xff11_0d12,   // VMUL.F16.
        0xef91_0942,   // VMUL.F16 (indexed).
        0xef91_0142,   // VMLA.F16 (indexed).
        0xef31_0f02,   // VMIN.F16.
        0xff11_0f02,   // VPMAX.F16.
        0xff31_0e12,   // VACGT.F16.
        0xef32_0f54,   // VRSQRTS.F16.
        0xffb5_0742,   // VABS.F16.
        0xffb5_0642,   // VCLT.F16 (compare with zero).
        0xffb7_05c2,   // VRSQRTE.F16.
        0xffb7_0642,   // VCVT.F16.S16 (non-fixed).
        0xffb7_07c2,   // VCVT.U16.F16 (non-fixed).
        0xff01_0f12,   // VMAXNM.F32.
        0xff31_0f12,   // VMINNM.F16.
        0xffba_0482,   // VRINTX.F32 D0,D2.
        0xffb6_05c2,   // VRINTZ.F16 Q0,Q1.
        0xffbb_00c2,   // VCVTA.U32.F32 Q0,Q1.
        0xffb7_0342,   // VCVTM.S16.F16 Q0,Q1.
        0xfc22_0813,   // VFMAL (non-indexed).
        0xfe14_087e,   // VFMSL (indexed).
        0xff11_0b12,   // VQRDMLAH (non-indexed).
        0xef92_0f68,   // VQRDMLSH (indexed).
    ]);
}

#[test]
fn thumb_fp_predicate_rejects_restricted_scalar_f32_f64_encodings() {
    check_restricted(&[
        0xfe81_0a02, // VMAXNM.F32.
        0xfe81_0b42, // VMINNM.F64.
        0xfe01_0a02, // VSELEQ.F32.
        0xfe21_0b02, // VSELGE.F64.
        0xfeb8_0a41, // VRINTA.F32.
        0xfebb_0b41, // VRINTM.F64.
        0xfebd_0a41, // VCVTN.U32.F32.
        0xfebe_0bc1, // VCVTP.S32.F64.
    ]);
}

#[test]
fn thumb_fp_predicate_retains_legal_width_and_encoding_neighbors() {
    for raw in [
        0xef01_0d02, // VADD.F32.
        0xef11_0802, // VADD.I16 (size field overlaps VADD.F16).
        0xffb6_0701, // VCVT.F32.F16 (precision).
        0xffb6_0602, // VCVT.F16.F32 (precision).
        0xefb8_0c52, // VCVT.F16.S16 (fixed-point).
        0xffb8_0d52, // VCVT.U16.F16 (fixed-point).
        0xffbb_0642, // VCVT.F32.S32 (non-fixed).
        0xeeb7_0a41, // VRINTX.F32 (scalar).
        0xeeb6_0bc1, // VRINTZ.F64 (scalar).
        0xeebd_0ac1, // VCVT.S32.F32 (scalar).
    ] {
        let (control, _, expected) = run(raw, None, false);
        let (result, _, after) = run(raw, Some(true), false);
        assert!(
            matches!(control, ExecResult::Continue),
            "{raw:08x}: {control:?}"
        );
        assert!(
            matches!(result, ExecResult::Continue),
            "{raw:08x}: {result:?}"
        );
        assert_eq!(after, expected, "{raw:08x}");
        let (result, before, after) = run(raw, Some(true), true);
        assert!(
            matches!(result, ExecResult::FpAccessTrap { target_el: 2, .. }),
            "{raw:08x}: {result:?}"
        );
        assert_eq!(after, before, "{raw:08x}");
    }
}

#[test]
fn thumb_simd_predicate_precedes_mixed_width_el2_access_trap() {
    for predicate_passes in [None, Some(false), Some(true)] {
        let mut cpu = mixed(SIMD_ADD_HALF, true, 2, false, true);
        let mut state = cpu.export_sregs();
        state.execution.as_mut().unwrap().features |= ArmFeatures::FP16.bits();
        cpu.import_sregs(&state).unwrap();
        let it_eq = if predicate_passes.is_some() {
            2 << 10
        } else {
            0
        };
        let z = u64::from(predicate_passes == Some(true)) << 30;
        cpu.set_pstate_bits(0x1f3 | it_eq | z).unwrap();
        let before = (cpu.get_simd(0), cpu.fpsr_value());
        let result = cpu.step();
        assert!(
            match predicate_passes {
                None => matches!(
                    result,
                    Err(ArmError::ArchitecturalException {
                        ec: 7,
                        target_el: Some(2),
                        ..
                    })
                ),
                Some(false) => matches!(result, Ok(CpuExit::Continue)),
                Some(true) => matches!(result, Err(ArmError::UndefinedInstruction(SIMD_ADD_HALF))),
            },
            "predicate={predicate_passes:?}: {result:?}"
        );
        let retired = u64::from(predicate_passes == Some(false));
        assert_eq!(cpu.instruction_count(), retired);
        assert_eq!(cpu.get_pc(), 0x100 + 4 * retired);
        assert_eq!((cpu.get_simd(0), cpu.fpsr_value()), before);
    }
}

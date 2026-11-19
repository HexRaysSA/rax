//! Arm VJCVT A1/T1 through the scalar FP access and exception paths.
use super::*;
use rax::isa::arm::aarch32::vfp::Fpscr;
use rax::isa::arm::decoder::ThumbDecoder;

const VJCVT: u32 = 0xeeb9_0bc1; // VJCVT.S32.F64 S0,D1 in both widths.
const CANARY: u64 = 0x1234_5678_fedc_ba98;
const FZ: u32 = 1 << 24;
const INPUT_STATUS: u32 = 0x80;
const INVALID: u32 = 1;
const INEXACT: u32 = 0x10;

fn execute_vjcvt(cpu: &mut Armv7Cpu, raw: u32) -> ExecResult {
    if !cpu.cpsr.t {
        return execute(cpu, raw);
    }
    let insn = ThumbDecoder::decode_32bit(raw).unwrap();
    Executor::new(cpu, &mut Memory32::new(4096, 0)).execute(&insn)
}

#[test]
fn vjcvt_rounds_toward_zero_wraps_and_updates_fpscr() {
    let cases = [
        (0.0, 0, true, 0),
        (-0.0, 0, false, 0),
        (-1.25, u32::MAX, false, INEXACT),
        (f64::from(i32::MIN), 0x8000_0000, true, 0),
        (f64::from(i32::MAX), 0x7fff_ffff, true, 0),
        (2147483647.5, 0x7fff_ffff, false, INEXACT),
        (4294967297.0, 1, false, INVALID),
        (-4294967297.0, u32::MAX, false, INVALID),
        (f64::MAX, 0, false, INVALID),
        (f64::INFINITY, 0, false, INVALID),
        (f64::NEG_INFINITY, 0, false, INVALID),
        (f64::NAN, 0, false, INVALID),
        (f64::from_bits(0x7ff0_0000_0000_0001), 0, false, INVALID),
        (f64::from_bits(1), 0, false, INEXACT),
        (-f64::from_bits(1), 0, false, INEXACT),
    ];
    for thumb in [false, true] {
        for fz in [false, true] {
            for (input, expected, zero, mut status) in cases {
                let mut cpu = Armv7Cpu::new();
                cpu.cp15.id_isar6 |= 1;
                cpu.cpsr.t = thumb;
                cpu.cpsr.n = true;
                let kept = (1 << 27) | (1 << 25) | (1 << 22) | 2 | if fz { FZ } else { 0 };
                cpu.vfp.fpscr = Fpscr::from_bits(kept | 0xf000_0000);
                cpu.vfp.write_d_bits(0, CANARY);
                cpu.vfp.write_d(1, input);
                if fz && input.is_subnormal() {
                    status = INPUT_STATUS;
                }
                let result = execute_vjcvt(&mut cpu, VJCVT);
                assert!(
                    matches!(result, ExecResult::Continue),
                    "{thumb}: {result:?}"
                );
                assert_eq!(
                    cpu.vfp.read_d_bits(0),
                    (CANARY & !u64::from(u32::MAX)) | u64::from(expected)
                );
                assert_eq!(cpu.vfp.read_d_bits(1), input.to_bits());
                assert_eq!(
                    cpu.vfp.fpscr.bits(),
                    kept | (u32::from(zero) << 30) | status
                );
                assert!(cpu.cpsr.n);
            }
        }
    }
}

#[test]
fn vjcvt_feature_predicate_and_register_checks_precede_access_traps() {
    for thumb in [false, true] {
        // feature, allowed predicate, narrow register bank, expect access trap
        for (feature, allowed, narrow, access_trap) in [
            (0, true, false, false),
            (2, true, false, false),
            (1, false, false, false),
            (1, true, true, false),
            (1, true, false, true),
        ] {
            let mut cpu = hyp();
            cpu.cp15.hcptr = 1 << 10;
            cpu.cp15.id_isar6 = feature;
            cpu.cpsr.t = thumb;
            cpu.cpsr.z = true;
            if narrow {
                cpu.vfp.mvfr0 = (cpu.vfp.mvfr0 & !15) | 1;
            }
            let mut raw = VJCVT | if narrow { 1 << 5 } else { 0 };
            if !allowed {
                if thumb {
                    cpu.cpsr.set_it_state(0, 8);
                } else {
                    raw &= 0x0fff_ffff; // EQ, with the predicate true.
                }
            }
            let before = (cpu.vfp.fpscr.bits(), cpu.vfp.dregs);
            let result = execute_vjcvt(&mut cpu, raw);
            assert!(
                if access_trap {
                    matches!(result, ExecResult::FpAccessTrap { target_el: 2, .. })
                } else {
                    matches!(result, ExecResult::Undefined)
                },
                "{thumb}/{feature}/{allowed}/{narrow}: {result:?}"
            );
            assert_eq!((cpu.vfp.fpscr.bits(), cpu.vfp.dregs), before);
        }
    }
}

#[test]
fn vjcvt_enabled_exception_preserves_destination_and_nzcv() {
    for (input, status, control) in [
        (f64::NAN, INVALID, 0),
        (1.5, INEXACT, 0),
        (f64::from_bits(1), INPUT_STATUS, FZ),
    ] {
        let mut cpu = Armv7Cpu::new();
        cpu.cp15.id_isar6 |= 1;
        cpu.vfp.mvfr0 |= 1 << 12;
        let fpscr = 0xb000_0000 | control | (status << 8);
        cpu.vfp.fpscr = Fpscr::from_bits(fpscr);
        cpu.vfp.write_d_bits(0, CANARY);
        cpu.vfp.write_d(1, input);
        let before = cpu.vfp.dregs;
        let result = execute_vjcvt(&mut cpu, VJCVT);
        assert!(
            matches!(result, ExecResult::Exception(rax::isa::arm::ExceptionType::FloatingPoint(bits)) if u32::from(bits) == status),
            "{result:?}"
        );
        assert_eq!(cpu.vfp.dregs, before);
        assert_eq!(cpu.vfp.fpscr.bits(), fpscr);
    }
}

//! FP16 core transfer and scalar packing: exact bits, aliases and validity.
use rax::isa::arm::aarch32::cpu::ProcessorMode;
use rax::isa::arm::aarch32::vfp::Fpscr;
use rax::isa::arm::decoder::{Aarch32Decoder, ThumbDecoder};
use rax::isa::arm::execution::FlatMemory;
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};

const SCALAR_HALF_WITH_ZERO_VECTOR_CONTROLS: [u32; 19] = [
    0xee31_0902, // VADD.F16
    0xee31_0942, // VSUB.F16
    0xee21_0902, // VMUL.F16
    0xee81_0902, // VDIV.F16
    0xee21_0942, // VNMUL.F16
    0xee01_0902, // VMLA.F16
    0xee01_0942, // VMLS.F16
    0xee11_0942, // VNMLA.F16
    0xee11_0902, // VNMLS.F16
    0xeeb0_09c1, // VABS.F16
    0xeeb1_0941, // VNEG.F16
    0xeeb1_09c1, // VSQRT.F16
    0xeeb7_0900, // VMOV.F16 (immediate)
    0xeea1_0902, // VFMA.F16
    0xeea1_0942, // VFMS.F16
    0xee91_0942, // VFNMA.F16
    0xee91_0902, // VFNMS.F16
    0xfeb0_0a41, // VMOVX.F16
    0xfeb0_0ac1, // VINS.F16
];

fn decode(raw: u32, thumb: bool) -> rax::isa::arm::decoder::DecodedInsn {
    if thumb {
        ThumbDecoder::decode_32bit(raw)
    } else {
        Aarch32Decoder::decode(raw)
    }
    .unwrap()
}
fn execute(cpu: &mut Armv7Cpu, raw: u32) -> ExecResult {
    let insn = decode(raw, cpu.cpsr.t);
    let mut memory = FlatMemory::new(4096, 0);
    Executor::new(cpu, &mut memory).execute(&insn)
}
fn cpu(thumb: bool) -> Armv7Cpu {
    let mut cpu = Armv7Cpu::new();
    cpu.cpsr.t = thumb;
    cpu.vfp.dregs.fill(0xcafebabe_dead1234);
    cpu.vfp.fpscr = Fpscr::from_bits(0xaec89f9f);
    cpu
}
#[test]
fn llvm_half_register_encodings_have_their_architectural_operations() {
    for thumb in [false, true] {
        for (raw, tag) in [
            (0xfeb00a41, "VMOVX_F16"),
            (0xfeb00ac1, "VINS_F16"),
            (0xee000910, "VMOV_F16_CORE"),
            (0xee110910, "VMOV_F16_CORE"),
        ] {
            assert_eq!(format!("{:?}", decode(raw, thumb).mnemonic), tag);
        }
    }
}
#[test]
fn extraction_zero_extends_the_source_high_half() {
    for thumb in [false, true] {
        let mut cpu = cpu(thumb);
        cpu.vfp.write_s_bits(2, 0xdead7c01);
        assert!(matches!(
            execute(&mut cpu, 0xfeb00a41),
            ExecResult::Continue
        ));
        assert_eq!(cpu.vfp.dregs[0], 0xcafebabe_0000dead);
        assert_eq!(cpu.vfp.fpscr.bits(), 0xaec89f9f);
    }
}
#[test]
fn insertion_uses_source_low_half_and_retains_destination_low_half() {
    for thumb in [false, true] {
        let mut cpu = cpu(thumb);
        cpu.vfp.write_s_bits(2, 0xdead7c01);
        assert!(matches!(
            execute(&mut cpu, 0xfeb00ac1),
            ExecResult::Continue
        ));
        assert_eq!(cpu.vfp.dregs[0], 0xcafebabe_7c011234);
        assert_eq!(cpu.vfp.fpscr.bits(), 0xaec89f9f);
    }
}
#[test]
fn core_to_half_transfer_zero_extends_without_nan_processing() {
    for thumb in [false, true] {
        let mut cpu = cpu(thumb);
        cpu.regs[0] = 0xffff7c01;
        assert!(matches!(
            execute(&mut cpu, 0xee000910),
            ExecResult::Continue
        ));
        assert_eq!(cpu.vfp.dregs[0], 0xcafebabe_00007c01);
        assert_eq!(cpu.vfp.fpscr.bits(), 0xaec89f9f);
    }
}
#[test]
fn half_to_core_transfer_zero_extends_without_nan_processing() {
    for thumb in [false, true] {
        let mut cpu = cpu(thumb);
        cpu.vfp.write_s_bits(2, 0xffff7c01);
        cpu.regs[0] = 0xdeadbeef;
        assert!(matches!(
            execute(&mut cpu, 0xee110910),
            ExecResult::Continue
        ));
        assert_eq!(cpu.regs[0], 0x7c01);
        assert_eq!(cpu.vfp.fpscr.bits(), 0xaec89f9f);
    }
}
#[test]
fn all_scalar_register_fields_and_aliases_preserve_other_state() {
    let mut count = 0;
    for thumb in [false, true] {
        for insert in [false, true] {
            for d in 0u8..32 {
                for m in 0u8..32 {
                    for source in [0xffff7c01, 0x8000ffff, 0x7e017fc1, 0xdeadbeef] {
                        let mut cpu = cpu(thumb);
                        cpu.vfp.write_s_bits(m, source);
                        let mut expected = cpu.vfp.clone();
                        let original = cpu.vfp.read_s_bits(d);
                        expected.write_s_bits(
                            d,
                            if insert {
                                source << 16 | original & 0xffff
                            } else {
                                source >> 16
                            },
                        );
                        let raw = if insert { 0xfeb00ac0 } else { 0xfeb00a40 }
                            | u32::from(d >> 1) << 12
                            | u32::from(d & 1) << 22
                            | u32::from(m >> 1)
                            | u32::from(m & 1) << 5;
                        let regs = cpu.regs;
                        let cpsr = cpu.cpsr.to_u32();
                        assert!(matches!(execute(&mut cpu, raw), ExecResult::Continue));
                        assert_eq!(cpu.vfp.dregs, expected.dregs, "raw={raw:08x} Thumb={thumb}");
                        assert_eq!(cpu.vfp.fpscr.bits(), 0xaec89f9f);
                        assert_eq!(cpu.regs, regs);
                        assert_eq!(cpu.cpsr.to_u32(), cpsr);
                        count += 1;
                    }
                }
            }
        }
    }
    assert_eq!(count, 16384);
}
#[test]
fn all_core_and_half_fields_preserve_other_registers_and_status() {
    let mut count = 0;
    for thumb in [false, true] {
        for to_core in [false, true] {
            for n in 0u8..32 {
                for t in 0usize..15 {
                    for source in [0xffff7c01, 0x8000ffff, 0x7e017fc1, 0xdeadbeef] {
                        let mut cpu = cpu(thumb);
                        cpu.vfp.write_s_bits(n, source);
                        cpu.regs[t] = source;
                        let mut expected = cpu.vfp.clone();
                        let mut regs = cpu.regs;
                        if to_core {
                            regs[t] = source & 0xffff;
                        } else {
                            expected.write_s_bits(n, source & 0xffff);
                        }
                        let raw = 0xee000910
                            | if to_core { 1 << 20 } else { 0 }
                            | u32::from(n >> 1) << 16
                            | u32::from(n & 1) << 7
                            | (t as u32) << 12;
                        let cpsr = cpu.cpsr.to_u32();
                        assert!(matches!(execute(&mut cpu, raw), ExecResult::Continue));
                        assert_eq!(cpu.vfp.dregs, expected.dregs, "raw={raw:08x} Thumb={thumb}");
                        assert_eq!(cpu.regs, regs);
                        assert_eq!(cpu.cpsr.to_u32(), cpsr);
                        assert_eq!(cpu.vfp.fpscr.bits(), 0xaec89f9f);
                        count += 1;
                    }
                }
            }
        }
    }
    assert_eq!(count, 7680);
}
#[test]
fn packing_rejects_nonzero_legacy_length_or_stride_without_changes() {
    for thumb in [false, true] {
        for raw in [0xfeb00a41, 0xfeb00ac1] {
            for extra in (1..8).map(|n| n << 16).chain((1..4).map(|n| n << 20)) {
                let mut cpu = cpu(thumb);
                cpu.vfp.mvfr0 |= 1 << 24;
                cpu.vfp.fpscr = Fpscr::from_bits(extra);
                let dregs = cpu.vfp.dregs;
                let regs = cpu.regs;
                let cpsr = cpu.cpsr.to_u32();
                assert!(matches!(execute(&mut cpu, raw), ExecResult::Undefined));
                assert_eq!(cpu.vfp.dregs, dregs);
                assert_eq!(cpu.regs, regs);
                assert_eq!(cpu.cpsr.to_u32(), cpsr);
                assert_eq!(cpu.vfp.fpscr.bits(), extra);
            }
            let mut cpu_without_short_vectors = cpu(thumb);
            cpu_without_short_vectors.vfp.fpscr = Fpscr::from_bits(0x0037_0000);
            cpu_without_short_vectors.vfp.write_s_bits(2, 0xdead7c01);
            assert!(matches!(
                execute(&mut cpu_without_short_vectors, raw),
                ExecResult::Continue
            ));
            assert_eq!(
                cpu_without_short_vectors.vfp.read_s_bits(0),
                if raw == 0xfeb0_0a41 {
                    0x0000_dead
                } else {
                    0x7c01_1234
                },
            );
            assert_eq!(cpu_without_short_vectors.vfp.fpscr.bits(), 0x0037_0000);
        }
    }
}

#[test]
fn scalar_half_controls_reject_every_nonzero_pair_before_fp_access() {
    for thumb in [false, true] {
        for raw in SCALAR_HALF_WITH_ZERO_VECTOR_CONTROLS {
            for short_vectors in [false, true] {
                for (len, stride) in (0..8).flat_map(|len| (0..4).map(move |stride| (len, stride)))
                {
                    let mut cpu = cpu(thumb);
                    cpu.cpsr.mode = ProcessorMode::Hyp as u8;
                    cpu.cp15.scr = 1;
                    cpu.cp15.nsacr = 1 << 10;
                    cpu.cp15.hcptr = 1 << 10;
                    cpu.vfp.mvfr0 |= u32::from(short_vectors) << 24;
                    let fpscr = (len << 16) | (stride << 20);
                    cpu.vfp.fpscr = Fpscr::from_bits(fpscr);
                    let before = (cpu.regs, cpu.vfp.dregs, cpu.cpsr.to_u32());
                    let result = execute(&mut cpu, raw);
                    let invalid = short_vectors && fpscr != 0;
                    assert!(
                        if invalid {
                            matches!(result, ExecResult::Undefined)
                        } else {
                            matches!(result, ExecResult::FpAccessTrap { target_el: 2, .. })
                        },
                        "raw={raw:08x}, Thumb={thumb}, ShortVectors={short_vectors}, FPSCR={fpscr:08x}: {result:?}",
                    );
                    assert_eq!(before, (cpu.regs, cpu.vfp.dregs, cpu.cpsr.to_u32()));
                    assert_eq!(cpu.vfp.fpscr.bits(), fpscr);
                }
            }
        }
    }
}

#[test]
fn scalar_half_controls_leave_core_transfers_and_conversion_admitted() {
    for thumb in [false, true] {
        for raw in [0xee00_0910, 0xee11_0910, 0xeeb8_0941, 0xeeb4_0941] {
            let mut cpu = cpu(thumb);
            cpu.vfp.mvfr0 |= 1 << 24;
            cpu.vfp.fpscr = Fpscr::from_bits(0x0031_0000);
            assert!(
                matches!(execute(&mut cpu, raw), ExecResult::Continue),
                "raw={raw:08x}, Thumb={thumb}",
            );
        }
    }
}
#[test]
fn half_moves_obey_vfp_enable_and_selected_it_unpredictable_policy() {
    for raw in [0xfeb00a41, 0xfeb00ac1, 0xee000910, 0xee110910] {
        for thumb in [false, true] {
            let mut cpu = cpu(thumb);
            cpu.vfp.fpexc = 0;
            assert!(matches!(execute(&mut cpu, raw), ExecResult::Exception(_)));
        }
        let mut cpu = cpu(true);
        cpu.cpsr.set_it_state(0, 8);
        cpu.cpsr.z = true;
        assert!(matches!(execute(&mut cpu, raw), ExecResult::Undefined));
    }
}
#[test]
fn forged_half_move_tags_and_core_pc_field_reject_without_effects() {
    use rax::isa::arm::decoder::Mnemonic;
    for thumb in [false, true] {
        for raw in [0xfeb00a41, 0xee000910] {
            let mut cpu = cpu(thumb);
            let mut insn = decode(raw, thumb);
            insn.mnemonic = Mnemonic::VINS_F16;
            let dregs = cpu.vfp.dregs;
            let regs = cpu.regs;
            let mut memory = FlatMemory::new(4096, 0);
            assert!(matches!(
                Executor::new(&mut cpu, &mut memory).execute(&insn),
                ExecResult::Undefined
            ));
            assert_eq!(cpu.vfp.dregs, dregs);
            assert_eq!(cpu.regs, regs);
            assert_eq!(cpu.vfp.fpscr.bits(), 0xaec89f9f);
        }
        assert_eq!(decode(0xee00f910, thumb).mnemonic, Mnemonic::UNDEFINED);
    }
}
#[test]
fn scalar_half_forms_keep_explicit_smir_unsupported_admission() {
    use rax::smir::ir::types::SourceArch;
    use rax::smir::lift::aarch32::Aarch32Lifter;
    use rax::smir::lift::thumb::ThumbLifter;
    use rax::smir::lift::{LiftContext, LiftError, SmirLifter};
    for raw in SCALAR_HALF_WITH_ZERO_VECTOR_CONTROLS
        .into_iter()
        .chain([0xee000910, 0xee110910])
    {
        for thumb in [false, true] {
            let bytes = if thumb {
                let hi = ((raw >> 16) as u16).to_le_bytes();
                let lo = (raw as u16).to_le_bytes();
                [hi[0], hi[1], lo[0], lo[1]]
            } else {
                raw.to_le_bytes()
            };
            let mut context = LiftContext::new(if thumb {
                SourceArch::Thumb
            } else {
                SourceArch::Aarch32
            });
            let mut lifter: Box<dyn SmirLifter> = if thumb {
                Box::new(ThumbLifter::new())
            } else {
                Box::new(Aarch32Lifter::new())
            };
            assert!(
                matches!(
                    lifter.lift_insn(0x1000, &bytes, &mut context),
                    Err(LiftError::Unsupported { addr: 0x1000, .. })
                ),
                "raw={raw:08x}, Thumb={thumb}"
            );
        }
    }
}
